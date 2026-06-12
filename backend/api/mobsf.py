"""
MobSF secondary/fallback static analysis gateway.
Surfaces MobSF findings alongside BluJay's own static results.
Requires MobSF running at settings.mobsf_url.
"""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.analysis import Analysis

router = APIRouter()


def _client():
    from core.mobsf_client import MobSFClient
    return MobSFClient(settings.mobsf_url, settings.mobsf_api_key)


class ScanRequest(BaseModel):
    analysis_id: int


@router.get("/status")
async def mobsf_status():
    """Check whether MobSF is reachable at the configured URL."""
    reachable = await _client().is_reachable()
    return {"reachable": reachable, "url": settings.mobsf_url}


@router.post("/scan")
async def run_scan(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Upload the APK already on disk (from a BluJay analysis) to MobSF and run a scan.
    Returns the MobSF scan_hash needed to fetch the report.
    """
    result = await db.execute(select(Analysis).where(Analysis.id == req.analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if not analysis.upload_path:
        raise HTTPException(400, "No APK path on record for this analysis")

    apk_path = Path(analysis.upload_path)
    if not apk_path.exists():
        raise HTTPException(400, "APK file not found on disk")

    client = _client()
    try:
        up = await client.upload(apk_path)
        scan_hash = up["hash"]
        scan_type = up.get("scan_type", "apk")
        file_name = up.get("file_name", apk_path.name)
        summary = await client.scan(scan_type, file_name, scan_hash)
        return {"scan_hash": scan_hash, "scan_type": scan_type, "summary": summary}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"MobSF error: {exc}") from exc


@router.get("/report/{scan_hash}")
async def get_report(scan_hash: str):
    """Fetch the JSON report for a completed MobSF scan."""
    try:
        return await _client().report_json(scan_hash)
    except Exception as exc:
        raise HTTPException(502, f"MobSF error: {exc}") from exc
