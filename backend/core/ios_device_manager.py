"""
iOS device detection using libimobiledevice CLI tools (idevice_id, ideviceinfo).
Detects USB-connected iOS devices and probes for jailbreak indicators via AFC2.

Requires libimobiledevice to be installed:
  Windows:  winget install libimobiledevice
  macOS:    brew install libimobiledevice
  Linux:    apt install libimobiledevice-utils
"""
import asyncio
import functools
import shutil
import subprocess
from pathlib import Path

import structlog

from config import settings
from schemas.ios_device import IosDeviceInfo

logger = structlog.get_logger()


def _resolve_tool(name: str) -> str | None:
    """Check configured libimobiledevice dir first, then fall back to PATH."""
    configured = Path(settings.libimobiledevice_dir) / name
    # Try with and without .exe extension (Windows vs Unix)
    for candidate in [configured, Path(str(configured) + ".exe")]:
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def _run_sync(*args: str, timeout: float = 10) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            timeout=timeout,
        )
        return (
            result.returncode,
            result.stdout.decode(errors="replace"),
            result.stderr.decode(errors="replace"),
        )
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not found"
    except Exception as exc:
        return -1, "", str(exc)


async def _run(*args: str, timeout: float = 10) -> tuple[int, str, str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, functools.partial(_run_sync, *args, timeout=timeout)
    )


async def _is_jailbroken(udid: str) -> bool:
    """
    Detect jailbreak by probing SSH over USB via iproxy.
    Jailbreaks almost universally install OpenSSH on port 22.
    iproxy forwards a local TCP port to the device's port 22 over USB.
    If we receive an SSH banner, the device is jailbroken.
    """
    import asyncio
    import socket
    import random

    iproxy = _resolve_tool("iproxy")
    if not iproxy:
        return False

    local_port = random.randint(49152, 65535)
    proc = None
    loop = asyncio.get_event_loop()

    def _start_iproxy():
        return subprocess.Popen(
            [iproxy, str(local_port), "22", udid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _probe_ssh() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=3) as s:
                banner = s.recv(64)
                return banner.startswith(b"SSH-")
        except Exception:
            return False

    try:
        proc = await loop.run_in_executor(None, _start_iproxy)
        # Give iproxy a moment to establish the tunnel
        await asyncio.sleep(1.5)
        return await loop.run_in_executor(None, _probe_ssh)
    except Exception:
        return False
    finally:
        if proc:
            proc.terminate()


async def pull_ipa(udid: str, bundle_id: str, output_dir: Path) -> Path:
    """
    Pull an installed app as an IPA from a connected iOS device.

    Tries two methods in order:
      1. Native Frida dump  — works on jailbroken devices with frida-server running.
                              Decrypts App Store apps from memory automatically.
                              Requires: pip install frida-tools
      2. ideviceinstaller --download — works for sideloaded / dev-signed apps;
                              most package-manager builds omit --download support.

    Raises RuntimeError with actionable instructions on failure.
    """
    from core.frida_dump import dump_ipa as frida_dump_ipa

    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Method 1: native Frida dump (preferred for jailbroken devices) ---
    try:
        return await frida_dump_ipa(udid, bundle_id, output_dir)
    except Exception as e:
        logger.warning("frida_dump failed, falling back to ideviceinstaller", error=str(e))
        frida_error = str(e)

    # --- Method 2: ideviceinstaller --download ---
    ideviceinstaller = _resolve_tool("ideviceinstaller")
    if not ideviceinstaller:
        raise RuntimeError(
            f"Frida dump failed ({frida_error}) and ideviceinstaller was not found. "
            "Ensure frida-server is running on the device (pip install frida-tools on host)."
        )

    rc, stdout, stderr = await _run(
        ideviceinstaller, "-u", udid,
        "--download", bundle_id,
        "--output", str(output_dir),
        timeout=120,
    )
    if rc != 0:
        combined = stderr.strip() or stdout.strip()
        if "unrecognized option" in combined and "--download" in combined:
            raise RuntimeError(
                f"Frida dump failed ({frida_error}) and this build of ideviceinstaller "
                "does not support --download. "
                "Start frida-server on the device and retry."
            )
        raise RuntimeError(f"ideviceinstaller failed (exit {rc}): {combined}")

    matches = list(output_dir.glob(f"{bundle_id}*.ipa"))
    if not matches:
        matches = list(output_dir.glob("*.ipa"))
    if not matches:
        raise RuntimeError("IPA not found in output directory after download")

    return max(matches, key=lambda p: p.stat().st_mtime)


async def _frida_ps_apps(udid: str) -> list[dict]:
    """
    Use `frida-ps -D <udid> -ai` to enumerate all installed apps.
    This is the approach used by frida-ios-dump and requires frida-server
    to be running on the jailbroken device.

    Output format (space-aligned columns):
      PID  Name                      Identifier
      ---  ------------------------  ---------------------------
        -  TikTok                    com.zhiliaoapp.musically
     1234  Safari                    com.apple.mobilesafari
    """
    frida_ps = shutil.which("frida-ps")
    if not frida_ps:
        return []

    rc, stdout, _ = await _run(frida_ps, "-D", udid, "-ai", timeout=15)
    if rc != 0 or not stdout.strip():
        return []

    results = []
    for line in stdout.splitlines()[2:]:  # skip header + separator
        line = line.rstrip()
        if not line:
            continue
        parts = line.split()
        # parts[0]=PID or '-', parts[-1]=bundle ID, parts[1:-1]=display name words
        if len(parts) < 3:
            continue
        identifier = parts[-1]
        name = " ".join(parts[1:-1])
        if not identifier or "." not in identifier:
            continue
        results.append({"bundle_id": identifier, "version": "", "name": name})

    return results


async def list_apps(udid: str) -> list[dict]:
    """
    Returns installed third-party apps on a connected iOS device.

    Merges three sources so apps from all install paths appear:
      1. ideviceinstaller -l     — standard App Store / sideloaded installs
      2. frida-ps -D <udid> -ai  — all apps visible to frida-server on a
                                   jailbroken device (frida-ios-dump approach),
                                   catches TrollStore / Sileo installs
      3. frida Python API        — fallback when frida-ps CLI is absent but
                                   the frida Python package is available
    """
    apps: dict[str, dict] = {}  # bundle_id → app dict

    # --- Source 1: ideviceinstaller ---
    ideviceinstaller = _resolve_tool("ideviceinstaller")
    if ideviceinstaller:
        rc, stdout, _ = await _run(ideviceinstaller, "-u", udid, "-l", timeout=20)
        if rc == 0 and stdout.strip():
            for line in stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Total:") or line.startswith("No apps"):
                    continue
                parts = [p.strip() for p in line.split(",", 2)]
                if not parts:
                    continue
                bundle_id = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                display_name = parts[2] if len(parts) > 2 else bundle_id
                if bundle_id:
                    apps[bundle_id] = {"bundle_id": bundle_id, "version": version, "name": display_name}

    # --- Source 2: frida-ps (frida-ios-dump style — jailbroken + frida-server) ---
    frida_ps_results = await _frida_ps_apps(udid)
    for entry in frida_ps_results:
        bid = entry["bundle_id"]
        if bid not in apps:
            apps[bid] = entry
        elif not apps[bid].get("name") or apps[bid]["name"] == bid:
            # Prefer the frida-ps display name if ideviceinstaller only gave us the bundle ID
            apps[bid]["name"] = entry["name"]

    # --- Source 3: Frida Python API (fallback when frida-ps CLI is absent) ---
    if not frida_ps_results:
        try:
            import frida
            import functools

            def _frida_apps() -> list[dict]:
                try:
                    mgr = frida.get_device_manager()
                    device = mgr.get_device(udid, timeout=5)
                    result = []
                    try:
                        entries = device.enumerate_applications(scope="full")
                    except Exception:
                        entries = device.enumerate_applications()
                    for app in entries:
                        identifier = getattr(app, "identifier", None) or ""
                        if not identifier or identifier.startswith("com.apple."):
                            continue
                        name = app.name or identifier
                        result.append({"bundle_id": identifier, "version": "", "name": name})
                    return result
                except Exception:
                    return []

            loop = asyncio.get_event_loop()
            frida_apps = await loop.run_in_executor(None, functools.partial(_frida_apps))
            for entry in frida_apps:
                bid = entry["bundle_id"]
                if bid not in apps:
                    apps[bid] = entry
        except ImportError:
            pass

    return sorted(apps.values(), key=lambda x: x["bundle_id"].lower())


async def get_devices() -> list[IosDeviceInfo]:
    """
    Returns a list of USB-connected iOS devices.
    Returns an empty list if libimobiledevice is not installed.
    """
    idevice_id = _resolve_tool("idevice_id")
    if not idevice_id:
        return []

    rc, stdout, _ = await _run(idevice_id, "-l", timeout=10)
    if rc != 0 or not stdout.strip():
        return []

    udids = [line.strip() for line in stdout.splitlines() if line.strip()]
    ideviceinfo = _resolve_tool("ideviceinfo")

    devices = []
    for udid in udids:
        name = None
        model = None
        ios_version = None
        jailbroken = False

        if ideviceinfo:
            rc, info_out, _ = await _run(ideviceinfo, "-u", udid, timeout=10)
            if rc == 0:
                for line in info_out.splitlines():
                    if ": " not in line:
                        continue
                    key, _, val = line.partition(": ")
                    key = key.strip()
                    val = val.strip()
                    if key == "DeviceName":
                        name = val
                    elif key == "ProductType":
                        model = val
                    elif key == "ProductVersion":
                        ios_version = val

            jailbroken = await _is_jailbroken(udid)

        devices.append(IosDeviceInfo(
            udid=udid,
            name=name,
            model=model,
            ios_version=ios_version,
            jailbroken=jailbroken,
        ))

    return devices
