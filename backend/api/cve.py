import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, AsyncSessionLocal
from models.cve import DetectedLibrary, CveMatch
from schemas.cve import CveScanResponse, DetectedLibraryOut, CveMatchOut

router = APIRouter()


@router.post("/scan/{analysis_id}", response_model=dict)
async def trigger_scan(
    analysis_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    from models.analysis import Analysis
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if analysis.status != "complete":
        raise HTTPException(400, "Analysis must be complete before CVE scan")

    from core.cve_correlator import run_cve_scan
    background_tasks.add_task(run_cve_scan, analysis_id, AsyncSessionLocal)
    return {"status": "scan_started"}


@router.get("/{analysis_id}/libraries", response_model=list[DetectedLibraryOut])
async def get_libraries(analysis_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DetectedLibrary)
        .where(DetectedLibrary.analysis_id == analysis_id)
        .order_by(DetectedLibrary.ecosystem, DetectedLibrary.name)
    )
    return result.scalars().all()


@router.get("/{analysis_id}/matches", response_model=list[CveMatchOut])
async def get_matches(
    analysis_id: int,
    severity: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(CveMatch).where(CveMatch.analysis_id == analysis_id)
    if severity:
        q = q.where(CveMatch.severity == severity.lower())
    q = q.order_by(CveMatch.cvss_score.desc().nullslast())
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{analysis_id}/summary", response_model=CveScanResponse)
async def get_summary(analysis_id: int, db: AsyncSession = Depends(get_db)):
    libs_result = await db.execute(
        select(DetectedLibrary).where(DetectedLibrary.analysis_id == analysis_id)
    )
    libs = libs_result.scalars().all()

    matches_result = await db.execute(
        select(CveMatch).where(CveMatch.analysis_id == analysis_id)
    )
    matches = matches_result.scalars().all()

    total_critical = sum(1 for m in matches if m.severity == "critical")
    total_high = sum(1 for m in matches if m.severity == "high")

    return CveScanResponse(
        libraries=[DetectedLibraryOut.model_validate(l) for l in libs],
        cve_matches=[CveMatchOut.model_validate(m) for m in matches],
        total_critical=total_critical,
        total_high=total_high,
    )
