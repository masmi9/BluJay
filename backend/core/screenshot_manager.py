"""
Screenshot capture via ADB and storage management.
"""
import asyncio
import base64
import io
from datetime import datetime
from pathlib import Path

import structlog
from PIL import Image

logger = structlog.get_logger()


async def capture_screenshot(serial: str) -> bytes:
    """Run `adb exec-out screencap -p` and return raw PNG bytes."""
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
