"""
Play Store APK downloader — pulls an APK by package name via apkeep,
then feeds it straight into BluJay's existing analysis pipeline.
"""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db

router = APIRouter()


class DownloadRequest(BaseModel):
    package_name: str
    email: str | None = None
    password: str | None = None


@router.post("")
async def download_apk(
    req: DownloadRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Download an APK from the Play Store by package name and kick off static analysis.
    Returns the new Analysis record (same shape as POST /analyses).
    """
    from core.playstore_downloader import download

    try:
        apk_path = await download(req.package_name, req.email, req.password)
    except FileNotFoundError as exc:
        raise HTTPException(503, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc

    # Reuse the existing analysis pipeline helper
    from api.analysis import _create_and_run
    return await _create_and_run(apk_path, apk_path.name, background_tasks, db)
