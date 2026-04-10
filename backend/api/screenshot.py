from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.screenshot import Screenshot
from schemas.screenshot import CaptureRequest, ScreenshotOut

router = APIRouter()


@router.post("/capture", response_model=ScreenshotOut, status_code=201)
async def capture_screenshot(body: CaptureRequest, db: AsyncSession = Depends(get_db)):
    from core.screenshot_manager import capture_screenshot as do_capture, save_screenshot

    try:
        data = await do_capture(body.serial)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))

    file_path, thumbnail_b64 = save_screenshot(
        body.session_id, data, body.label, settings.workspace_dir
    )

    ss = Screenshot(
        session_id=body.session_id,
        label=body.label,
        file_path=str(file_path),
        thumbnail_b64=thumbnail_b64,
    )
    db.add(ss)
    await db.commit()
    await db.refresh(ss)
    return ss


@router.get("", response_model=list[ScreenshotOut])
async def list_screenshots(session_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Screenshot)
        .where(Screenshot.session_id == session_id)
        .order_by(Screenshot.captured_at)
    )
    return result.scalars().all()


@router.get("/{screenshot_id}/image")
async def get_image(screenshot_id: int, db: AsyncSession = Depends(get_db)):
    ss = await db.get(Screenshot, screenshot_id)
    if not ss:
        raise HTTPException(404, "Screenshot not found")
    path = Path(ss.file_path)
    if not path.exists():
        raise HTTPException(404, "Image file missing from disk")
    return FileResponse(str(path), media_type="image/png")


@router.delete("/{screenshot_id}", status_code=204)
async def delete_screenshot(screenshot_id: int, db: AsyncSession = Depends(get_db)):
    ss = await db.get(Screenshot, screenshot_id)
    if not ss:
        raise HTTPException(404, "Screenshot not found")
    path = Path(ss.file_path)
    if path.exists():
        path.unlink()
    await db.delete(ss)
    await db.commit()
