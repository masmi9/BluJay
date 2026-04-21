"""
Screenshot capture via ADB (Android) or idevicescreenshot (iOS) and storage management.
"""
import asyncio
import base64
import io
import tempfile
from datetime import datetime
from pathlib import Path

import structlog
from PIL import Image

logger = structlog.get_logger()


async def capture_screenshot(serial: str, platform: str = "android") -> bytes:
    """Capture a screenshot and return raw PNG bytes.

    Android: uses `adb exec-out screencap -p`
    iOS:     uses `idevicescreenshot -u <udid> <tmpfile>`
    """
    if platform == "ios":
        return await _capture_ios(serial)
    return await _capture_android(serial)


async def _capture_android(serial: str) -> bytes:
    from config import settings

    proc = await asyncio.create_subprocess_exec(
        str(settings.adb_path), "-s", serial, "exec-out", "screencap", "-p",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"adb screencap failed: {stderr.decode(errors='replace')}")
    if not stdout:
        raise RuntimeError("adb screencap returned empty output")
    return stdout


async def _capture_ios(udid: str) -> bytes:
    from config import settings

    # idevicescreenshot writes to a file — use a temp path
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    tool = settings.libimobiledevice_dir / "idevicescreenshot"
    # On Windows the binary has .exe extension
    if not tool.exists():
        tool = settings.libimobiledevice_dir / "idevicescreenshot.exe"
    if not tool.exists():
        raise RuntimeError(
            "idevicescreenshot not found — ensure libimobiledevice is installed at "
            f"{settings.libimobiledevice_dir}"
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            str(tool), "-u", udid, str(tmp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"idevicescreenshot failed: {stderr.decode(errors='replace')}")
        if not tmp_path.exists() or tmp_path.stat().st_size == 0:
            raise RuntimeError("idevicescreenshot produced no output")
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


def save_screenshot(session_id: int, data: bytes, label: str, workspace_dir: Path) -> tuple[Path, str]:
    """
    Write PNG to disk and generate a base64 JPEG thumbnail.
    Returns (file_path, thumbnail_b64).
    """
    screenshots_dir = workspace_dir / "screenshots" / str(session_id)
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label) or "screenshot"
    filename = f"{ts}_{safe_label}.png"
    file_path = screenshots_dir / filename

    file_path.write_bytes(data)

    # Generate thumbnail: 100px wide, JPEG quality 70
    img = Image.open(io.BytesIO(data))
    ratio = 100 / img.width
    thumb_size = (100, int(img.height * ratio))
    thumb = img.resize(thumb_size, Image.LANCZOS)
    if thumb.mode == "RGBA":
        thumb = thumb.convert("RGB")
    buf = io.BytesIO()
    thumb.save(buf, format="JPEG", quality=70)
    thumbnail_b64 = base64.b64encode(buf.getvalue()).decode()

    return file_path, thumbnail_b64
