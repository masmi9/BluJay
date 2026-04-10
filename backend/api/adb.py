from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

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


@router.get("/{serial}/screenshot")
async def device_screenshot(serial: str):
    """Convenience endpoint — streams a PNG screenshot directly."""
    from core.screenshot_manager import capture_screenshot
    try:
        data = await capture_screenshot(serial)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))
    return Response(content=data, media_type="image/png")
