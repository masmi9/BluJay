import asyncio
import json
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.pci import PciFinding, PciScanJob
from schemas.pci import (
    PciFindingOut, PciFullScanRequest, PciScanJobOut, PciScanRequest,
)

router = APIRouter()
_running_jobs: dict[int, asyncio.Task] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _job_out(job: PciScanJob) -> dict:
    return {
        "id": job.id,
        "target_urls": json.loads(job.target_urls),
        "scope_config": job.scope_config,
        "categories": json.loads(job.categories),
        "scan_profile": job.scan_profile,
        "status": job.status,
        "phase": job.phase,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "finding_count": job.finding_count,
        "hosts_found": job.hosts_found,
        "ports_open": job.ports_open,
        "pages_crawled": job.pages_crawled,
        "processors_detected": json.loads(job.processors_detected),
        "flow_steps_count": job.flow_steps_count,
        "error": job.error,
        "created_at": job.created_at,
    }


# ── Quick web scan ────────────────────────────────────────────────────────────

@router.post("/jobs", response_model=PciScanJobOut)
async def start_pci_scan(body: PciScanRequest, db: AsyncSession = Depends(get_db)):
    urls = [u.strip() for u in body.target_urls if u.strip()]
    if not urls:
        raise HTTPException(400, "Provide at least one target URL")
    job = PciScanJob(
        target_urls=json.dumps(urls),
        categories=json.dumps(body.categories),
        scan_profile=body.scan_profile,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    asyncio.create_task(_run_web_job(job.id, urls))
    return _job_out(job)


# ── Full PCI scan ─────────────────────────────────────────────────────────────

@router.post("/full-scan", response_model=PciScanJobOut)
async def start_full_scan(body: PciFullScanRequest, db: AsyncSession = Depends(get_db)):
    from core.pci_scope import parse_scope
    try:
        scope = parse_scope(body.scope_config)
    except Exception as exc:
        raise HTTPException(400, f"Invalid scope config: {exc}")

    # Extract seed URLs for storage
    seed_urls = [
        t.get("value", "")
        for t in scope.raw_targets
        if t.get("type") == "url" or "://" in t.get("value", "")
    ]

    job = PciScanJob(
        target_urls=json.dumps(seed_urls or [scope.name]),
        scope_config=body.scope_config,
        categories=json.dumps([]),
        scan_profile=body.scan_profile or scope.assessment_type,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    asyncio.create_task(_run_full_job(job.id, scope))
    return _job_out(job)


# ── Scope validation ──────────────────────────────────────────────────────────

@router.post("/scope/validate")
async def validate_scope(body: PciFullScanRequest):
    from core.pci_scope import parse_scope
    try:
        scope = parse_scope(body.scope_config)
        return {
            "valid": True,
            "name": scope.name,
            "target_count": len(scope.raw_targets),
            "checks": vars(scope.checks),
            "scan_profile": scope.assessment_type,
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


# ── Job management ────────────────────────────────────────────────────────────

@router.get("/jobs", response_model=list[PciScanJobOut])
async def list_pci_jobs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PciScanJob).order_by(PciScanJob.created_at.desc()).limit(50))
    return [_job_out(j) for j in result.scalars().all()]


@router.get("/jobs/{job_id}", response_model=PciScanJobOut)
async def get_pci_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return _job_out(job)


@router.delete("/jobs/{job_id}")
async def cancel_pci_job(job_id: int, db: AsyncSession = Depends(get_db)):
    task = _running_jobs.pop(job_id, None)
    if task:
        task.cancel()
    job = await db.get(PciScanJob, job_id)
    if job and job.status == "running":
        job.status = "error"
        job.error = "Cancelled by user"
        job.finished_at = datetime.utcnow()
        await db.commit()
    return {"status": "cancelled"}


@router.delete("/jobs/{job_id}/delete")
async def delete_pci_job(job_id: int, db: AsyncSession = Depends(get_db)):
    task = _running_jobs.pop(job_id, None)
    if task:
        task.cancel()
    await db.execute(sa_delete(PciFinding).where(PciFinding.job_id == job_id))
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    await db.delete(job)
    await db.commit()
    return {"status": "deleted"}


@router.get("/jobs/{job_id}/flow-steps")
async def get_flow_steps(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if not job.flow_steps_json:
        return []
    return json.loads(job.flow_steps_json)


@router.get("/jobs/{job_id}/findings", response_model=list[PciFindingOut])
async def get_pci_findings(job_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PciFinding).where(PciFinding.job_id == job_id).order_by(PciFinding.created_at)
    )
    return result.scalars().all()


# ── Report endpoints ──────────────────────────────────────────────────────────

@router.get("/jobs/{job_id}/report/json")
async def get_report_json(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404)
    if not job.report_json:
        raise HTTPException(404, "Report not yet generated. Wait for scan to complete.")
    return Response(
        content=job.report_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="pci_report_{job_id}.json"'},
    )


@router.get("/jobs/{job_id}/report/executive")
async def get_report_executive(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404)
    if not job.report_html_exec:
        raise HTTPException(404, "Report not yet generated.")
    return Response(
        content=job.report_html_exec,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="pci_executive_{job_id}.html"'},
    )


@router.get("/jobs/{job_id}/report/technical")
async def get_report_technical(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(PciScanJob, job_id)
    if not job:
        raise HTTPException(404)
    if not job.report_html_tech:
        raise HTTPException(404, "Report not yet generated.")
    return Response(
        content=job.report_html_tech,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="pci_technical_{job_id}.html"'},
    )


# ── Background runners ────────────────────────────────────────────────────────

async def _persist_findings(job_id: int, findings) -> None:
    from database import AsyncSessionLocal
    import json as _json
    async with AsyncSessionLocal() as db:
        for f in findings:
            db.add(PciFinding(
                job_id=job_id,
                url=getattr(f, "target", ""),
                host=urlparse(getattr(f, "target", "//")).netloc or getattr(f, "target", ""),
                check_name=f.check_name,
                severity=f.severity,
                category=f.category,
                phase=f.phase,
                title=f.title,
                detail=f.detail,
                evidence=f.evidence.notes[:500] if f.evidence.notes else None,
                evidence_json=_json.dumps(f.evidence.to_dict()),
                remediation=f.remediation.description[:500] if f.remediation.description else None,
                pci_req=f.pci_req or None,
                port=f.port or None,
                service=f.service or None,
                cvss_score=f.cvss_score or None,
                cve_ids=_json.dumps(f.cve_ids) if f.cve_ids else None,
                plugin_id=f.plugin_id or None,
            ))
        await db.commit()


async def _run_web_job(job_id: int, target_urls: list[str]) -> None:
    from database import AsyncSessionLocal
    from core.pci_scanner import scan_url_pci
    from core.pci_models import PciScanSummary
    from core.pci_report import generate_json_report, generate_html_executive, generate_html_technical

    async with AsyncSessionLocal() as db:
        job = await db.get(PciScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.phase = "web_checks"
        job.started_at = datetime.utcnow()
        await db.commit()

    all_findings = []
    all_processors: set[str] = set()
    flow_results = []
    error = None

    try:
        task = asyncio.current_task()
        if task:
            _running_jobs[job_id] = task

        # Static web checks
        for url in target_urls:
            f, procs = await scan_url_pci(url)
            all_findings += f
            all_processors.update(procs)

        # Persist static findings immediately so they're never lost
        await _persist_findings(job_id, all_findings)

        # Interactive payment flow tests — isolated so any failure doesn't suppress static findings
        async with AsyncSessionLocal() as db:
            j = await db.get(PciScanJob, job_id)
            if j:
                j.phase = "payment_flow"
                await db.commit()

        try:
            from core.pci_payment_flow import run_payment_flow_tests
            flow_results = await run_payment_flow_tests(target_urls)
            flow_findings = [f for fr in flow_results for f in fr.findings]
            if flow_findings:
                await _persist_findings(job_id, flow_findings)
                all_findings += flow_findings
        except Exception as flow_exc:
            flow_results = []

        summary = PciScanSummary(
            scope_name=target_urls[0] if target_urls else "Quick Scan",
            scan_profile="web_only",
            target_count=len(target_urls),
            processors_detected=sorted(all_processors),
        )
        report_json = generate_json_report(all_findings, summary)
        report_exec = generate_html_executive(all_findings, summary)
        report_tech = generate_html_technical(all_findings, summary)

    except asyncio.CancelledError:
        error = "Cancelled"
    except Exception as exc:
        error = str(exc)[:500]
        report_json = report_exec = report_tech = None

    async with AsyncSessionLocal() as db:
        job = await db.get(PciScanJob, job_id)
        if job:
            job.status = "error" if error else "done"
            job.finished_at = datetime.utcnow()
            job.phase = None
            job.finding_count = len(all_findings)
            job.processors_detected = json.dumps(sorted(all_processors))
            job.flow_steps_json = json.dumps([fr.to_dict() for fr in flow_results])
            job.flow_steps_count = len(flow_results)
            if error:
                job.error = error
            if not error:
                job.report_json = report_json
                job.report_html_exec = report_exec
                job.report_html_tech = report_tech
            await db.commit()

    _running_jobs.pop(job_id, None)


async def _run_full_job(job_id: int, scope) -> None:
    from database import AsyncSessionLocal
    from core.pci_scanner import run_full_pci_scan
    from core.pci_report import generate_json_report, generate_html_executive, generate_html_technical

    async with AsyncSessionLocal() as db:
        job = await db.get(PciScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        await db.commit()

    error = None
    all_findings = []

    async def on_progress(phase: str, msg: str) -> None:
        async with AsyncSessionLocal() as db:
            j = await db.get(PciScanJob, job_id)
            if j:
                j.phase = phase
                await db.commit()

    try:
        task = asyncio.current_task()
        if task:
            _running_jobs[job_id] = task

        all_findings, summary, flow_results = await run_full_pci_scan(scope, on_progress, job_id)
        await _persist_findings(job_id, all_findings)

        report_json = generate_json_report(all_findings, summary)
        report_exec = generate_html_executive(all_findings, summary)
        report_tech = generate_html_technical(all_findings, summary)

    except asyncio.CancelledError:
        error = "Cancelled"
        summary = None
        flow_results = []
        report_json = report_exec = report_tech = None
    except Exception as exc:
        error = str(exc)[:500]
        summary = None
        flow_results = []
        report_json = report_exec = report_tech = None

    async with AsyncSessionLocal() as db:
        job = await db.get(PciScanJob, job_id)
        if job:
            job.status = "error" if error else "done"
            job.finished_at = datetime.utcnow()
            job.phase = None
            job.finding_count = len(all_findings)
            job.flow_steps_json = json.dumps([fr.to_dict() for fr in flow_results])
            job.flow_steps_count = len(flow_results)
            if summary:
                job.hosts_found = summary.hosts_live
                job.ports_open = summary.ports_open
                job.pages_crawled = summary.pages_crawled
                job.processors_detected = json.dumps(sorted(summary.processors_detected))
            if error:
                job.error = error
            if not error:
                job.report_json = report_json
                job.report_html_exec = report_exec
                job.report_html_tech = report_tech
            await db.commit()

    _running_jobs.pop(job_id, None)
