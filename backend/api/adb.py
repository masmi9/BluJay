import asyncio
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from core import adb_manager
from schemas.adb import DeviceInfo, InstallResult, LaunchRequest

router = APIRouter()


@router.get("", response_model=list[DeviceInfo])
async def list_devices():
    return await adb_manager.get_devices()


@router.post("/{serial}/install", response_model=InstallResult)
async def install_apk(serial: str, apk_path: str):
    path = Path(apk_path)
    if not path.exists():
        raise HTTPException(404, f"APK not found: {apk_path}")
    return await adb_manager.install_apk(serial, path)


@router.post("/{serial}/launch")
async def launch_app(serial: str, body: LaunchRequest):
    success = await adb_manager.launch_app(serial, body.package_name, body.activity)
    if not success:
        raise HTTPException(500, "Failed to launch app")
    return {"status": "launched"}


@router.post("/{serial}/uninstall", response_model=InstallResult)
async def uninstall(serial: str, package: str):
    return await adb_manager.uninstall_package(serial, package)


@router.get("/{serial}/packages")
async def list_packages(serial: str, third_party_only: bool = True):
    """
    Returns installed packages with their on-device APK paths.
    Defaults to third-party (user-installed) apps only.
    """
    return await adb_manager.list_packages_detailed(serial, third_party_only=third_party_only)


@router.post("/{serial}/proxy/set")
async def set_proxy(serial: str, host: str, port: int):
    success = await adb_manager.set_proxy(serial, host, port)
    return {"success": success}


@router.post("/{serial}/proxy/clear")
async def clear_proxy(serial: str):
    success = await adb_manager.clear_proxy(serial)
    return {"success": success}


# ── Drozer IPC / attack surface testing ──────────────────────────────────────

class DrozerRunRequest(BaseModel):
    module: str
    args: list[str] = []
    drozer_port: int = 31415


def _drozer_available() -> bool:
    return shutil.which("drozer") is not None


async def _drozer_cmd(serial: str, port: int, module: str, args: list[str]) -> dict[str, Any]:
    """Forward ADB port and run a drozer module command non-interactively."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, lambda: adb_manager._run_sync("forward", f"tcp:{port}", f"tcp:{port}", serial=serial)
    )

    cmd_parts = ["drozer", "console", "connect", "--server", f"127.0.0.1:{port}", "--command", f"run {module} {' '.join(args)}"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        return {
            "module": module,
            "args": args,
            "output": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
            "returncode": proc.returncode,
        }
    except asyncio.TimeoutError:
        raise HTTPException(504, "Drozer command timed out after 30s")
    except Exception as e:
        raise HTTPException(500, f"Drozer execution error: {e}")


@router.post("/{serial}/drozer/setup")
async def drozer_setup(serial: str, port: int = 31415):
    """Forward ADB port 31415 to prepare for drozer console connection."""
    if not _drozer_available():
        raise HTTPException(422, "drozer not found in PATH — install with: pip install drozer")
    loop = asyncio.get_event_loop()
    rc, out, err = await loop.run_in_executor(
        None, lambda: adb_manager._run_sync("forward", f"tcp:{port}", f"tcp:{port}", serial=serial)
    )
    return {"status": "port_forwarded", "serial": serial, "port": port, "detail": out or err}


@router.post("/{serial}/drozer/run")
async def drozer_run(serial: str, body: DrozerRunRequest):
    """Run an arbitrary drozer module command against the device."""
    if not _drozer_available():
        raise HTTPException(422, "drozer not found in PATH — install with: pip install drozer")
    return await _drozer_cmd(serial, body.drozer_port, body.module, body.args)


@router.post("/{serial}/drozer/attack-surface/{package}")
async def drozer_attack_surface(serial: str, package: str, port: int = 31415):
    """Enumerate the exported attack surface of a package via drozer."""
    if not _drozer_available():
        raise HTTPException(422, "drozer not found in PATH — install with: pip install drozer")

    # Run all four attack surface checks in sequence
    checks = [
        ("app.package.attacksurface", [package]),
        ("app.activity.info",         ["-a", package]),
        ("app.service.info",          ["-a", package]),
        ("app.provider.info",         ["-a", package]),
        ("app.broadcast.info",        ["-a", package]),
    ]
    results = {}
    for module, args in checks:
        key = module.split(".")[-1]
        results[key] = await _drozer_cmd(serial, port, module, args)

    return {"package": package, "serial": serial, "checks": results}


@router.get("/{serial}/screenshot")
async def device_screenshot(serial: str):
    """Convenience endpoint — streams a PNG screenshot directly."""
    from core.screenshot_manager import capture_screenshot
    try:
        data = await capture_screenshot(serial)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))
    return Response(content=data, media_type="image/png")
