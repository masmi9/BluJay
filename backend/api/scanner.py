import asyncio
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.scanner import ActiveScanJob, ScanFinding
from models.session import ProxyFlow
from schemas.scanner import (
    ActiveScanJobOut, FindingsResponse, ScanFindingOut, StartActiveScanRequest,
    ScanUrlRequest, ScanUrlResult, ACTIVE_CHECKS,
)

router = APIRouter()

# In-memory job tasks (job_id → asyncio.Task)
_running_jobs: dict[int, asyncio.Task] = {}


def _job_out(job: ActiveScanJob) -> dict:
    return {
        "id": job.id,
        "session_id": job.session_id,
        "flow_ids": json.loads(job.flow_ids),
        "checks": json.loads(job.checks),
        "status": job.status,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "finding_count": job.finding_count,
        "requests_sent": job.requests_sent,
        "error": job.error,
        "created_at": job.created_at,
    }


# ── Passive findings ──────────────────────────────────────────────────────────

@router.get("/findings", response_model=FindingsResponse)
async def get_findings(
    session_id: int | None = Query(None),
    scan_type: str | None = Query(None),
    severity: str | None = Query(None),
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    q = select(ScanFinding)
    if session_id is not None:
        q = q.where(ScanFinding.session_id == session_id)
    if scan_type:
        q = q.where(ScanFinding.scan_type == scan_type)
    if severity:
        q = q.where(ScanFinding.severity == severity)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    items = (await db.execute(q.order_by(ScanFinding.timestamp.desc()).offset(skip).limit(limit))).scalars().all()
    return {"total": total, "items": items}


@router.post("/scan-url", response_model=ScanUrlResult)
async def scan_url(body: ScanUrlRequest, db: AsyncSession = Depends(get_db)):
    """Fetch a URL and immediately run all passive checks against it."""
    import httpx
    from urllib.parse import urlparse
    from core.passive_scanner import run_passive_checks

    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "BluJay-Scanner/1.0"})
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch URL: {e}")

    host = urlparse(url).netloc
    flow = {
        "url": str(resp.url),
        "host": host,
        "method": "GET",
        "request_headers": {},
        "request_body": "",
        "response_status": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body": resp.text[:100_000],
        "tls": url.startswith("https://"),
        "content_type": resp.headers.get("content-type", ""),
    }

    raw_findings = run_passive_checks(flow)
    saved: list[ScanFinding] = []
    for f in raw_findings:
        sf = ScanFinding(
            session_id=body.session_id,
            flow_id=None,
            scan_type="passive",
            check_name=f.check_name,
            severity=f.severity,
            url=str(resp.url),
            host=host,
            title=f.title,
            detail=f.detail,
            evidence=f.evidence or None,
            remediation=f.remediation or None,
        )
        db.add(sf)
    await db.commit()
    # Refresh to get IDs
    for sf in saved:
        await db.refresh(sf)

    # Re-query so we have full ORM objects with IDs
    from sqlalchemy import desc
    result = await db.execute(
        select(ScanFinding)
        .where(ScanFinding.url == str(resp.url), ScanFinding.scan_type == "passive")
        .order_by(desc(ScanFinding.timestamp))
        .limit(len(raw_findings) + 1)
    )
    items = result.scalars().all()
    return {"url": str(resp.url), "findings": items}


@router.delete("/findings")
async def clear_findings(session_id: int | None = Query(None), db: AsyncSession = Depends(get_db)):
    q = delete(ScanFinding)
    if session_id is not None:
        q = q.where(ScanFinding.session_id == session_id)
    await db.execute(q)
    await db.commit()
    return {"status": "cleared"}


# ── Active scan jobs ──────────────────────────────────────────────────────────

@router.get("/jobs", response_model=list[ActiveScanJobOut])
async def list_jobs(session_id: int | None = Query(None), db: AsyncSession = Depends(get_db)):
    q = select(ActiveScanJob).order_by(ActiveScanJob.created_at.desc()).limit(50)
    if session_id is not None:
        q = q.where(ActiveScanJob.session_id == session_id)
    jobs = (await db.execute(q)).scalars().all()
    return [_job_out(j) for j in jobs]


@router.post("/jobs", response_model=ActiveScanJobOut)
async def start_scan(body: StartActiveScanRequest, db: AsyncSession = Depends(get_db)):
    if not body.flow_ids and not body.target_urls:
        raise HTTPException(400, "Provide at least one flow_id or target_url")
    invalid = [c for c in body.checks if c not in ACTIVE_CHECKS]
    if invalid:
        raise HTTPException(400, f"Unknown checks: {invalid}. Valid: {ACTIVE_CHECKS}")

    job = ActiveScanJob(
        session_id=body.session_id,
        flow_ids=json.dumps(body.flow_ids),
        checks=json.dumps(body.checks),
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    asyncio.create_task(_run_job(job.id, body.flow_ids, body.checks, body.target_urls))
    return _job_out(job)


@router.get("/jobs/{job_id}", response_model=ActiveScanJobOut)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = (await db.execute(select(ActiveScanJob).where(ActiveScanJob.id == job_id))).scalar_one_or_none()
    if not job:
        raise HTTPException(404, "Job not found")
    return _job_out(job)


@router.delete("/jobs/{job_id}")
async def cancel_job(job_id: int, db: AsyncSession = Depends(get_db)):
    task = _running_jobs.pop(job_id, None)
    if task:
        task.cancel()
    job = (await db.execute(select(ActiveScanJob).where(ActiveScanJob.id == job_id))).scalar_one_or_none()
    if job and job.status == "running":
        job.status = "error"
        job.error = "Cancelled"
        job.finished_at = datetime.utcnow()
        await db.commit()
    return {"status": "cancelled"}


# ── Job runner ────────────────────────────────────────────────────────────────

async def _run_job(job_id: int, flow_ids: list[str], checks: list[str], target_urls: list[str] | None = None) -> None:
    from database import AsyncSessionLocal
    from core.active_scanner import run_active_scan
    from api.ws import broadcast_scanner

    async with AsyncSessionLocal() as db:
        job = (await db.execute(select(ActiveScanJob).where(ActiveScanJob.id == job_id))).scalar_one_or_none()
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        await db.commit()

        flows = []

        # Flows from proxy history
        if flow_ids:
            rows = (await db.execute(
                select(ProxyFlow).where(ProxyFlow.id.in_(flow_ids))
            )).scalars().all()
            for r in rows:
                flows.append({
                    "id": r.id,
                    "url": r.url,
                    "method": r.method,
                    "request_headers": r.request_headers,
                    "request_body": (r.request_body or b"").decode(errors="replace"),
                    "response_status": r.response_status,
                })

        # Synthetic flows from direct URL input
        for url in (target_urls or []):
            from urllib.parse import urlparse
            parsed = urlparse(url.strip())
            if parsed.scheme and parsed.netloc:
                flows.append({
                    "id": f"url-{url}",
                    "url": url.strip(),
                    "method": "GET",
                    "request_headers": "{}",
                    "request_body": "",
                    "response_status": None,
                })

    async def on_finding(jid: int, finding, flow_id: str):
        async with AsyncSessionLocal() as db:
            sf = ScanFinding(
                session_id=job.session_id,
                flow_id=flow_id,
                scan_job_id=jid,
                scan_type="active",
                check_name=finding.check_name,
                severity=finding.severity,
                url=finding.url,
                host=_host(finding.url),
                title=finding.title,
                detail=finding.detail,
                evidence=finding.evidence,
                remediation=finding.remediation,
            )
            db.add(sf)
            await db.commit()
            await db.refresh(sf)
        await broadcast_scanner(jid, {"type": "finding", "data": {
            "id": sf.id, "check_name": sf.check_name, "severity": sf.severity,
            "title": sf.title, "url": sf.url, "evidence": sf.evidence,
        }})

    async def on_progress(jid: int, requests_sent: int):
        async with AsyncSessionLocal() as db:
            j = (await db.execute(select(ActiveScanJob).where(ActiveScanJob.id == jid))).scalar_one_or_none()
            if j:
                j.requests_sent = requests_sent
                await db.commit()
        await broadcast_scanner(jid, {"type": "progress", "requests_sent": requests_sent})

    async def on_done(jid: int, finding_count: int, requests_sent: int, error: str | None):
        async with AsyncSessionLocal() as db:
            j = (await db.execute(select(ActiveScanJob).where(ActiveScanJob.id == jid))).scalar_one_or_none()
            if j:
                j.status = "error" if error else "done"
                j.finished_at = datetime.utcnow()
                j.finding_count = finding_count
                j.requests_sent = requests_sent
                j.error = error
                await db.commit()
        await broadcast_scanner(jid, {"type": "done", "finding_count": finding_count, "error": error})
        _running_jobs.pop(jid, None)

    task = asyncio.current_task()
    if task:
        _running_jobs[job_id] = task

    await run_active_scan(job_id, flows, checks, on_finding, on_progress, on_done)


def _host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc
    except Exception:
        return ""
