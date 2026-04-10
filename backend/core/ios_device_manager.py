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

from config import settings
from schemas.ios_device import IosDeviceInfo


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
    Uses ideviceinstaller --download. Requires a jailbroken device or
    a development/sideloaded app (App Store apps are encrypted).
    Returns the path to the downloaded IPA file.
    Raises RuntimeError on failure.
    """
    ideviceinstaller = _resolve_tool("ideviceinstaller")
    if not ideviceinstaller:
        raise RuntimeError("ideviceinstaller not found — install libimobiledevice")

    output_dir.mkdir(parents=True, exist_ok=True)
    rc, stdout, stderr = await _run(
        ideviceinstaller, "-u", udid,
        "--download", bundle_id,
        "--output", str(output_dir),
        timeout=120,
    )
    if rc != 0:
        raise RuntimeError(
            f"ideviceinstaller failed (exit {rc}): {stderr.strip() or stdout.strip()}"
        )

    # ideviceinstaller writes <BundleId>-<version>.ipa or <BundleId>.ipa
    matches = list(output_dir.glob(f"{bundle_id}*.ipa"))
    if not matches:
        matches = list(output_dir.glob("*.ipa"))
    if not matches:
        raise RuntimeError("IPA not found in output directory after download")

    return max(matches, key=lambda p: p.stat().st_mtime)


async def list_apps(udid: str) -> list[dict]:
    """
    Returns installed third-party apps on a connected iOS device.
    Requires ideviceinstaller (part of libimobiledevice).
    Output format per line: com.example.app, 1.0.0, App Display Name
    """
    ideviceinstaller = _resolve_tool("ideviceinstaller")
    if not ideviceinstaller:
        return []

    rc, stdout, _ = await _run(ideviceinstaller, "-u", udid, "-l", timeout=20)
    if rc != 0 or not stdout.strip():
        return []

    apps = []
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
            apps.append({"bundle_id": bundle_id, "version": version, "name": display_name})

    apps.sort(key=lambda x: x["bundle_id"].lower())
    return apps


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
