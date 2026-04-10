from fastapi import APIRouter

from config import settings
from core import tool_detector

router = APIRouter()


@router.get("")
async def get_settings():
    return {
        "host": settings.host,
        "port": settings.port,
        "workspace_dir": str(settings.workspace_dir),
        "java_path": settings.java_path,
        "apktool_jar": str(settings.apktool_jar),
        "jadx_path": str(settings.jadx_path),
        "adb_path": str(settings.adb_path),
        "proxy_host": settings.proxy_host,
        "proxy_port": settings.proxy_port,
        "log_level": settings.log_level,
    }


@router.patch("")
async def update_settings(body: dict):
    allowed = {
        "java_path", "apktool_jar", "jadx_path", "adb_path",
        "proxy_host", "proxy_port", "log_level",
    }
    for key, value in body.items():
        if key in allowed and hasattr(settings, key):
            setattr(settings, key, value)
    return await get_settings()


@router.get("/tools")
async def tools_status():
    return await tool_detector.check_all()
