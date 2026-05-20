import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.ai_agent import AIAgentFinding, AIAgentScan

router = APIRouter()

# In-memory cancellation flags keyed by scan_id
_cancel_flags: dict[int, list[bool]] = {}


# ── Request / Response schemas ─────────────────────────────────────────────

class StartScanRequest(BaseModel):
    target_url: str
    protocol_type: str = "openai_compat"  # openai_compat | mcp | a2a | rest
    probe_categories: list[str] = ["infra", "prompt_injection"]
    session_id: int | None = None


class ScanStatusResponse(BaseModel):
    id: int
    status: str
    finding_count: int
    duration_seconds: float | None
    error: str | None


# ── Helpers ────────────────────────────────────────────────────────────────

def _finding_to_dict(f: AIAgentFinding) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "evidence": f.evidence,
        "probe_id": f.probe_id,
        "request_payload": f.request_payload,
        "raw_response": f.raw_response,
        "confirmed": f.confirmed,
        "timestamp": f.timestamp.isoformat() if f.timestamp else None,
    }


def _scan_to_dict(s: AIAgentScan, include_findings: bool = False) -> dict:
    d = {
        "id": s.id,
        "status": s.status,
        "target_url": s.target_url,
        "protocol_type": s.protocol_type,
        "probe_categories": json.loads(s.probe_categories or "[]"),
        "finding_count": s.finding_count,
        "session_id": s.session_id,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "duration_seconds": s.duration_seconds,
        "error": s.error,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
    if include_findings:
        d["findings"] = [_finding_to_dict(f) for f in (s.findings or [])]
    return d


# ── Endpoints ──────────────────────────────────────────────────────────────

@router.post("/scan")
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    scan = AIAgentScan(
        session_id=body.session_id,
        status="pending",
        target_url=body.target_url,
        protocol_type=body.protocol_type,
        probe_categories=json.dumps(body.probe_categories),
        finding_count=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    flag: list[bool] = [False]
    _cancel_flags[scan.id] = flag

    # Patch the runner to use our cancellation flag
    async def _run_with_flag(scan_id: int) -> None:
        from scanners.ai_agent import runner as _runner

        async with __import__("database").AsyncSessionLocal() as _db:
            _scan = await _db.get(AIAgentScan, scan_id)
            if not _scan:
                return
            _scan.status = "running"
            _scan.started_at = datetime.now(timezone.utc)
            await _db.commit()

            categories: list[str] = json.loads(_scan.probe_categories or "[]")
            all_findings: list[dict] = []

            try:
                if "infra" in categories:
                    from scanners.ai_agent.probes.infra_check import run_all as _infra
                    all_findings.extend(await _infra(_scan.target_url, flag))

                if "prompt_injection" in categories and not flag[0]:
                    from scanners.ai_agent.probes.prompt_injection import run_all as _pi
                    all_findings.extend(await _pi(_scan.target_url, _scan.protocol_type, flag))

                for f in all_findings:
                    _db.add(AIAgentFinding(
                        scan_id=scan_id,
                        category=f["category"],
                        severity=f["severity"],
                        title=f["title"],
                        detail=f["detail"],
                        evidence=f.get("evidence"),
                        probe_id=f["probe_id"],
                        request_payload=f.get("request_payload"),
                        raw_response=f.get("raw_response"),
                        confirmed=f.get("confirmed", False),
                    ))

                completed_at = datetime.now(timezone.utc)
                _scan.status = "cancelled" if flag[0] else "complete"
                _scan.finding_count = len(all_findings)
                _scan.findings_json = json.dumps([f["probe_id"] for f in all_findings])
                _scan.completed_at = completed_at
                _scan.duration_seconds = (completed_at - _scan.started_at).total_seconds()
                await _db.commit()

            except Exception as exc:
                _scan.status = "error"
                _scan.error = str(exc)[:500]
                _scan.completed_at = datetime.now(timezone.utc)
                await _db.commit()
            finally:
                _cancel_flags.pop(scan_id, None)

    background_tasks.add_task(_run_with_flag, scan.id)
    return {"id": scan.id, "status": "pending"}


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(AIAgentScan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanStatusResponse(
        id=scan.id,
        status=scan.status,
        finding_count=scan.finding_count,
        duration_seconds=scan.duration_seconds,
        error=scan.error,
    )


@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AIAgentScan).where(AIAgentScan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings_result = await db.execute(
        select(AIAgentFinding).where(AIAgentFinding.scan_id == scan_id)
        .order_by(AIAgentFinding.id)
    )
    findings = findings_result.scalars().all()
    d = _scan_to_dict(scan)
    d["findings"] = [_finding_to_dict(f) for f in findings]
    return d


@router.get("/scans")
async def list_scans(
    session_id: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(AIAgentScan).order_by(AIAgentScan.id.desc())
    if session_id is not None:
        q = q.where(AIAgentScan.session_id == session_id)
    result = await db.execute(q)
    scans = result.scalars().all()
    return [_scan_to_dict(s) for s in scans]


@router.post("/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    flag = _cancel_flags.get(scan_id)
    if flag is not None:
        flag[0] = True
    scan = await db.get(AIAgentScan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status in ("pending", "running"):
        scan.status = "cancelled"
        await db.commit()
    return {"id": scan_id, "status": scan.status}


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    scan = await db.get(AIAgentScan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.delete(scan)
    await db.commit()
    return {"deleted": True}
