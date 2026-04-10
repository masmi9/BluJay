"""
Async wrapper around the adb command-line tool.
Uses run_in_executor + subprocess.run so it works on Windows SelectorEventLoop.
"""
import asyncio
import functools
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import AsyncIterator

from config import settings
from schemas.adb import DeviceInfo, InstallResult, LogcatLine


def _resolve_adb() -> str:
    configured = settings.adb_path
    if Path(str(configured)).exists():
        return str(configured)
    found = shutil.which("adb")
    return found or "adb"


_ADB = _resolve_adb()


def _run_sync(*args: str, serial: str | None = None, timeout: float = 30) -> tuple[int, str, str]:
    cmd = [_ADB]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        result = subprocess.run(
            cmd,
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
        return -1, "", "adb not found"
    except Exception as exc:
        return -1, "", str(exc)


async def _run(*args: str, serial: str | None = None, timeout: float = 30) -> tuple[int, str, str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, functools.partial(_run_sync, *args, serial=serial, timeout=timeout)
    )


async def get_devices() -> list[DeviceInfo]:
    rc, stdout, _ = await _run("devices", "-l")
    devices = []
    for line in stdout.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        state = parts[1]
        attrs: dict[str, str] = {}
        for part in parts[2:]:
            if ":" in part:
                k, _, v = part.partition(":")
                attrs[k] = v
        devices.append(DeviceInfo(
            serial=serial,
            state=state,
            product=attrs.get("product"),
            model=attrs.get("model"),
            transport_id=attrs.get("transport_id"),
        ))
    return devices


async def install_apk(serial: str, apk_path: Path) -> InstallResult:
    rc, stdout, stderr = await _run("install", "-r", "-t", str(apk_path), serial=serial, timeout=120)
    combined = (stdout + stderr).strip()
    success = "Success" in combined
    return InstallResult(success=success, message=combined)


async def uninstall_package(serial: str, package: str) -> InstallResult:
    rc, stdout, stderr = await _run("uninstall", package, serial=serial)
    combined = (stdout + stderr).strip()
    return InstallResult(success=rc == 0, message=combined)


async def launch_app(serial: str, package: str, activity: str | None = None) -> bool:
    if activity:
        component = f"{package}/{activity}"
        rc, _, _ = await _run("shell", "am", "start", "-n", component, serial=serial)
    else:
        rc, _, _ = await _run(
            "shell", "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1",
            serial=serial,
        )
    return rc == 0


async def set_proxy(serial: str, host: str, port: int) -> bool:
    rc, _, _ = await _run("shell", "settings", "put", "global", "http_proxy", f"{host}:{port}", serial=serial)
    return rc == 0


async def clear_proxy(serial: str) -> bool:
    rc, _, _ = await _run("shell", "settings", "put", "global", "http_proxy", ":0", serial=serial)
    return rc == 0


async def list_packages(serial: str) -> list[str]:
    rc, stdout, _ = await _run("shell", "pm", "list", "packages", serial=serial)
    packages = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            packages.append(line[len("package:"):])
    return sorted(packages)


async def list_packages_detailed(serial: str, third_party_only: bool = False) -> list[dict]:
    """
    Returns list of {package, apk_path, third_party} dicts.
    Uses `pm list packages -f` to get the APK path for each package in one call.
    -3 flag limits to user-installed packages only.
    """
    flags = ["-f", "-3"] if third_party_only else ["-f"]
    rc, stdout, _ = await _run("shell", "pm", "list", "packages", *flags, serial=serial)
    packages = []
    for line in stdout.splitlines():
        line = line.strip()
        # format: package:/data/app/com.example-1/base.apk=com.example
        if not line.startswith("package:"):
            continue
        content = line[len("package:"):]
        if "=" not in content:
            continue
        apk_path, _, pkg_name = content.rpartition("=")
        if pkg_name:
            packages.append({
                "package": pkg_name.strip(),
                "apk_path": apk_path.strip(),
                "third_party": third_party_only,
            })
    return sorted(packages, key=lambda x: x["package"])


async def get_apk_paths(serial: str, package: str) -> list[str]:
    """
    Returns all APK paths for a package (base APK + any split APKs).
    Strips \\r so paths are clean on Windows where adb shell uses CRLF.
    """
    rc, stdout, stderr = await _run("shell", "pm", "path", package, serial=serial)
    paths = []
    for line in stdout.splitlines():
        line = line.strip().rstrip("\r")
        if line.startswith("package:"):
            path = line[len("package:"):]
            if path:
                paths.append(path)
    if not paths:
        raise RuntimeError(f"pm path failed for {package}: {stderr.strip() or 'package not found'}")
    return paths


async def get_apk_path(serial: str, package: str) -> str:
    """
    Returns the primary APK path for a package.
    For split APKs, returns base.apk; otherwise returns the first path found.
    """
    paths = await get_apk_paths(serial, package)
    for p in paths:
        if p.endswith("base.apk"):
            return p
    return paths[0]


async def pull_apk(serial: str, package: str, dest_dir: Path) -> Path:
    """
    Pulls the base APK for the given package from the device to dest_dir.
    Returns the local path of the pulled APK.
    """
    remote_path = await get_apk_path(serial, package)
    dest = dest_dir / f"{package}.apk"
    rc, stdout, stderr = await _run("pull", remote_path, str(dest), serial=serial, timeout=120)
    if rc != 0:
        raise RuntimeError(f"adb pull failed: {(stderr or stdout).strip()}")
    return dest


async def push_file(serial: str, local_path: Path, remote_path: str) -> bool:
    rc, _, _ = await _run("push", str(local_path), remote_path, serial=serial, timeout=60)
    return rc == 0


async def push_cert(serial: str, cert_path: Path) -> dict:
    """
    Pushes the mitmproxy CA cert to the device's Downloads folder.
    Creates the directory first, tries common Android path variants.
    """
    # Ensure the destination directory exists on the device
    await _run("shell", "mkdir", "-p", "/sdcard/Download", serial=serial)

    remote = "/sdcard/Download/mitmproxy-ca-cert.pem"
    rc, stdout, stderr = await _run("push", str(cert_path), remote, serial=serial, timeout=30)
    if rc == 0:
        return {"pushed": True, "remote_path": remote}

    # Fallback: some devices use /sdcard/Downloads (with 's')
    await _run("shell", "mkdir", "-p", "/sdcard/Downloads", serial=serial)
    remote2 = "/sdcard/Downloads/mitmproxy-ca-cert.pem"
    rc2, _, stderr2 = await _run("push", str(cert_path), remote2, serial=serial, timeout=30)
    if rc2 == 0:
        return {"pushed": True, "remote_path": remote2}

    return {
        "pushed": False,
        "remote_path": None,
        "error": (stderr2 or stderr).strip(),
    }


async def is_package_installed(serial: str, package: str) -> bool:
    rc, stdout, _ = await _run("shell", "pm", "list", "packages", package, serial=serial)
    return f"package:{package}" in stdout


async def forward_port(serial: str, local_port: int, remote_port: int) -> bool:
    """Set up a persistent ADB port forward (survives beyond a single command)."""
    rc, _, _ = await _run("forward", f"tcp:{local_port}", f"tcp:{remote_port}", serial=serial)
    return rc == 0


async def start_service(serial: str, package: str, service_class: str) -> bool:
    """Start an Android foreground service via am start-foreground-service (Android 8+)."""
    component = f"{package}/{service_class}"
    rc, _, _ = await _run("shell", "am", "start-foreground-service", "-n", component, serial=serial)
    return rc == 0


async def stream_logcat(
    serial: str,
    package: str | None = None,
    stop_event: asyncio.Event | None = None,
) -> AsyncIterator[LogcatLine]:
    """
    Yields LogcatLine objects from adb logcat.
    Uses subprocess.Popen in a daemon thread + asyncio.Queue so it works on
    Windows SelectorEventLoop (asyncio.create_subprocess_exec is not supported there).
    """
    cmd = [_ADB, "-s", serial, "logcat", "-v", "threadtime"]

    if package:
        rc, stdout, _ = await _run("shell", "pidof", package, serial=serial)
        pid = stdout.strip().split()[0] if rc == 0 and stdout.strip() else None
        if pid:
            cmd += ["--pid", pid]

    log_re = re.compile(
        r"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+\d+\s+([VDIWEF])\s+([^:]+?)\s*:\s*(.*)"
    )

    loop = asyncio.get_event_loop()
    queue: asyncio.Queue[LogcatLine | None] = asyncio.Queue(maxsize=1000)

    def _reader():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            try:
                for raw in proc.stdout:
                    if stop_event and stop_event.is_set():
                        break
                    line = raw.decode(errors="replace").rstrip()
                    m = log_re.match(line)
                    if m:
                        entry = LogcatLine(
                            ts=m.group(1),
                            pid=m.group(2),
                            level=m.group(3),
                            tag=m.group(4).strip(),
                            message=m.group(5),
                        )
                        asyncio.run_coroutine_threadsafe(queue.put(entry), loop)
            finally:
                proc.kill()
                proc.wait()
        finally:
            asyncio.run_coroutine_threadsafe(queue.put(None), loop)

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()

    while True:
        entry = await queue.get()
        if entry is None:
            break
        yield entry
