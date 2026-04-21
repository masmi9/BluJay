import asyncio
import hashlib
import json
from pathlib import Path

import aiofiles
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.analysis import Analysis, StaticFinding
from schemas.analysis import (
    AnalysisDetail,
    AnalysisSummary,
    FindingsResponse,
    ParsedManifest,
    StaticFindingOut,
    SourceEntry,
)

router = APIRouter()

# analysis_id -> asyncio.Queue for progress events
_progress_queues: dict[int, asyncio.Queue] = {}


class FromDeviceRequest(BaseModel):
    serial: str
    package: str


def get_progress_queue(analysis_id: int) -> asyncio.Queue | None:
    return _progress_queues.get(analysis_id)


@router.post("", response_model=AnalysisSummary, status_code=201)
async def upload_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted")

    upload_path = settings.uploads_dir / file.filename
    async with aiofiles.open(upload_path, "wb") as f:
        await f.write(await file.read())

    return await _create_and_run(upload_path, file.filename, background_tasks, db)


async def _create_and_run(
    apk_path: Path,
    filename: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession,
) -> Analysis:
    """Shared helper: hash APK, deduplicate, create Analysis row, start pipeline."""
    content = apk_path.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()

    existing = await db.execute(select(Analysis).where(Analysis.apk_sha256 == sha256))
    analysis = existing.scalar_one_or_none()
    if analysis:
        return analysis

    analysis = Analysis(
        apk_filename=filename,
        apk_sha256=sha256,
        upload_path=str(apk_path),
        status="pending",
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[analysis.id] = queue

    from core.apk_analyzer import run_analysis
    from database import AsyncSessionLocal
    background_tasks.add_task(run_analysis, analysis.id, apk_path, queue, AsyncSessionLocal)

    return analysis


@router.post("/from-device", response_model=AnalysisSummary, status_code=201)
async def analyze_from_device(
    body: FromDeviceRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Pulls the APK for `package` from the connected ADB device identified by `serial`,
    saves it to the uploads directory, then runs the full static analysis pipeline.
    """
    from core import adb_manager

    # Verify device is reachable
    devices = await adb_manager.get_devices()
    serials = {d.serial for d in devices if d.state == "device"}
    if body.serial not in serials:
        raise HTTPException(400, f"Device {body.serial!r} not connected or not authorised")

    try:
        apk_path = await adb_manager.pull_apk(body.serial, body.package, settings.uploads_dir)
    except RuntimeError as e:
        raise HTTPException(500, str(e))

    return await _create_and_run(apk_path, f"{body.package}.apk", background_tasks, db)


@router.get("", response_model=list[AnalysisSummary])
async def list_analyses(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Analysis).order_by(Analysis.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/{analysis_id}", response_model=AnalysisDetail)
async def get_analysis(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    return analysis


@router.delete("/{analysis_id}", status_code=204)
async def delete_analysis(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    await db.delete(analysis)
    await db.commit()


@router.post("/{analysis_id}/reanalyze", response_model=AnalysisSummary)
async def reanalyze(
    analysis_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Re-runs the full static analysis pipeline for an existing analysis.
    Clears all previous findings and resets metadata fields so a fresh
    parse of the manifest (with any parser fixes applied) populates them.
    """
    from sqlalchemy import delete as sa_delete

    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    apk_path = Path(analysis.upload_path) if analysis.upload_path else None
    if not apk_path or not apk_path.exists():
        raise HTTPException(409, "Original APK file no longer on disk — cannot re-analyze")

    # Clear previous findings
    await db.execute(sa_delete(StaticFinding).where(StaticFinding.analysis_id == analysis_id))

    # Reset metadata and pipeline state
    analysis.status = "pending"
    analysis.error_message = None
    analysis.package_name = None
    analysis.version_name = None
    analysis.version_code = None
    analysis.min_sdk = None
    analysis.target_sdk = None
    analysis.decompile_path = None
    analysis.jadx_path = None
    await db.commit()
    await db.refresh(analysis)

    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues[analysis_id] = queue

    from core.apk_analyzer import run_analysis
    from database import AsyncSessionLocal
    background_tasks.add_task(run_analysis, analysis_id, apk_path, queue, AsyncSessionLocal)

    return analysis


@router.get("/{analysis_id}/manifest")
async def get_manifest(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if not analysis.decompile_path:
        raise HTTPException(409, "Decompile not yet complete")
    manifest_path = Path(analysis.decompile_path) / "AndroidManifest.xml"
    if not manifest_path.exists():
        raise HTTPException(404, "AndroidManifest.xml not found in decompile output")
    from core.manifest_parser import parse_manifest
    return parse_manifest(manifest_path)


@router.get("/{analysis_id}/permissions")
async def get_permissions(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if not analysis.decompile_path:
        raise HTTPException(409, "Decompile not yet complete")
    manifest_path = Path(analysis.decompile_path) / "AndroidManifest.xml"
    if not manifest_path.exists():
        return []
    from core.manifest_parser import parse_manifest
    from core.permission_analyzer import classify_permissions
    data = parse_manifest(manifest_path)
    return classify_permissions(data.get("permissions", []))


@router.get("/{analysis_id}/findings", response_model=FindingsResponse)
async def get_findings(
    analysis_id: int,
    severity: str | None = Query(None),
    category: str | None = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    q = select(StaticFinding).where(StaticFinding.analysis_id == analysis_id)
    if severity:
        q = q.where(StaticFinding.severity == severity)
    if category:
        q = q.where(StaticFinding.category == category)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    items_q = q.order_by(StaticFinding.id).offset(skip).limit(limit)
    items = (await db.execute(items_q)).scalars().all()

    from core.finding_enricher import enrich
    enriched = []
    for f in items:
        extra = enrich(f.rule_id, f.category)
        out = StaticFindingOut.model_validate(f)
        out.impact = extra["impact"]
        out.attack_path = extra["attack_path"]
        enriched.append(out)

    return {"total": total, "items": enriched}


@router.get("/{analysis_id}/source")
async def list_source(
    analysis_id: int,
    path: str = Query(""),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    base = Path(analysis.jadx_path or analysis.decompile_path or "")
    if not base.exists():
        raise HTTPException(409, "Source not yet available")

    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(400, "Path traversal detected")

    if not target.exists():
        raise HTTPException(404, "Path not found")

    entries = []
    if target.is_dir():
        for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name)):
            entries.append(SourceEntry(
                path=str(child.relative_to(base)),
                is_dir=child.is_dir(),
                size=child.stat().st_size if child.is_file() else None,
            ))
    return entries


@router.get("/{analysis_id}/source/file")
async def read_source_file(
    analysis_id: int,
    path: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    base = Path(analysis.jadx_path or analysis.decompile_path or "")
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(400, "Path traversal detected")
    if not target.is_file():
        raise HTTPException(404, "File not found")

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise HTTPException(500, str(e))

    return {"path": path, "content": content}
