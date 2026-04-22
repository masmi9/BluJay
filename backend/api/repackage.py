"""
APK Repackage + Resign API.
"""
import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.analysis import Analysis

router = APIRouter()

# job_id → state dict (in-memory; good enough for one-at-a-time use)
_jobs: dict[int, dict] = {}
_job_counter = 0


class RepackageRequest(BaseModel):
    analysis_id: int
    ssl_bypass: bool = True
    root_bypass: bool = False
    debuggable: bool = True
    backup_enabled: bool = False
    custom_smali: dict[str, str] = {}


async def _run_job(job_id: int, analysis: Analysis, req: RepackageRequest) -> None:
    from core.repackage_engine import PatchOptions, repackage

    _jobs[job_id]["status"] = "running"
    apk_path = Path(analysis.upload_path) if analysis.upload_path else None
    if not apk_path or not apk_path.exists():
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = "APK file not found on disk"
        return

    existing_decoded = Path(analysis.decompile_path) if analysis.decompile_path else None
    opts = PatchOptions(
        ssl_bypass=req.ssl_bypass,
        root_bypass=req.root_bypass,
        debuggable=req.debuggable,
        backup_enabled=req.backup_enabled,
        custom_smali=req.custom_smali,
    )

    result = await repackage(analysis.id, apk_path, existing_decoded, opts)
    if result.success:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["signed_apk"] = str(result.signed_apk or result.output_apk)
        _jobs[job_id]["patches"] = result.patches_applied
        if result.error:
            _jobs[job_id]["warning"] = result.error
    else:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = result.error
        _jobs[job_id]["patches"] = result.patches_applied


@router.post("/start")
async def start_repackage(
    req: RepackageRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    global _job_counter
    analysis = await db.get(Analysis, req.analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if analysis.platform != "android":
        raise HTTPException(400, "Repackage only supported for Android APKs")

    _job_counter += 1
    job_id = _job_counter
    _jobs[job_id] = {
        "id": job_id,
        "analysis_id": req.analysis_id,
        "status": "pending",
        "patches": [],
        "signed_apk": None,
        "error": None,
        "warning": None,
    }
    background_tasks.add_task(_run_job, job_id, analysis, req)
    return {"job_id": job_id, "status": "pending"}


@router.get("/{job_id}/status")
async def job_status(job_id: int):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/{job_id}/download")
async def download_apk(job_id: int):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "done":
        raise HTTPException(400, f"Job is not done (status: {job['status']})")
    apk_path = Path(job["signed_apk"])
    if not apk_path.exists():
        raise HTTPException(500, "Output APK not found on disk")
    return FileResponse(
        str(apk_path),
        media_type="application/vnd.android.package-archive",
        filename=f"patched-{job_id}.apk",
    )


@router.get("/jobs")
async def list_jobs():
    return list(_jobs.values())
