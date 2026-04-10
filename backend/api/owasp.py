"""
OWASP Dynamic Scan API — wraps AODS (dyna.py).
"""
import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core import adb_manager
from core.owasp_scanner import get_progress_queue, run_scan
from database import get_db
from models.owasp import OwaspScan

router = APIRouter()

# scan_id -> asyncio.Queue for SSE/WS progress
_scan_queues: dict[int, asyncio.Queue] = {}


class StartScanRequest(BaseModel):
    apk_path: str = ""
    package_name: str
    mode: str = "deep"          # deep | quick
    platform: str = "android"   # android | ios
    analysis_id: int | None = None
    device_serial: str | None = None   # if set, pull APK from device


@router.post("", status_code=201, summary="Start an OWASP dynamic scan")
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    if body.device_serial:
        # Pull APK from the connected device into the workspace
        pulled_dir = settings.uploads_dir / "pulled"
        pulled_dir.mkdir(parents=True, exist_ok=True)
        try:
            apk = await adb_manager.pull_apk(body.device_serial, body.package_name, pulled_dir)
        except RuntimeError as exc:
            raise HTTPException(400, f"Failed to pull APK from device: {exc}")
    else:
        apk = Path(body.apk_path)
        if not apk.exists():
            raise HTTPException(404, f"APK not found: {body.apk_path}")

    scan = OwaspScan(
        platform=body.platform,
        apk_path=str(apk),
        package_name=body.package_name,
        mode=body.mode,
        analysis_id=body.analysis_id,
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(run_scan, scan.id, apk, body.package_name, body.mode, body.platform)
    return {"id": scan.id, "status": "pending"}


@router.get("", summary="List all OWASP scans")
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(OwaspScan).order_by(OwaspScan.created_at.desc()).offset(skip).limit(limit)
        )
    ).scalars().all()
    return [_summary(r) for r in rows]


@router.get("/{scan_id}", summary="Get scan details + findings")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    row = await _get_or_404(scan_id, db)
    return {
        **_summary(row),
        "findings": json.loads(row.findings_json or "[]"),
        "summary": json.loads(row.summary_json or "{}"),
        "has_html": bool(row.report_html),
    }


@router.get("/{scan_id}/findings", summary="Paginated findings for a scan")
async def get_findings(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    severity: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    row = await _get_or_404(scan_id, db)
    findings = json.loads(row.findings_json or "[]")
    if severity:
        findings = [f for f in findings if (f.get("severity") or "").lower() == severity.lower()]
    total = len(findings)
    return {"total": total, "items": findings[skip: skip + limit]}


@router.get("/{scan_id}/report", summary="Download HTML report")
async def get_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    from fastapi.responses import HTMLResponse
    row = await _get_or_404(scan_id, db)
    if not row.report_html:
        raise HTTPException(404, "HTML report not yet generated")
    return HTMLResponse(content=row.report_html)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    row = await _get_or_404(scan_id, db)
    await db.delete(row)
    await db.commit()


# ── helpers ──────────────────────────────────────────────────────────────────

def _summary(row: OwaspScan) -> dict:
    findings = json.loads(row.findings_json or "[]")
    by_sev: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or f.get("risk_level") or "unknown").lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat(),
        "analysis_id": row.analysis_id,
        "platform": row.platform,
        "apk_path": row.apk_path,
        "package_name": row.package_name,
        "mode": row.mode,
        "status": row.status,
        "progress": row.progress,
        "finding_count": len(findings),
        "by_severity": by_sev,
        "duration_s": row.duration_s,
        "error": row.error,
    }


async def _get_or_404(scan_id: int, db: AsyncSession) -> OwaspScan:
    row = (await db.execute(select(OwaspScan).where(OwaspScan.id == scan_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Scan not found")
    return row
