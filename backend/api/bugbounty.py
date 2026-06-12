"""
Bug Bounty recon workflow.
Orchestrates existing BluJay modules into a single structured hunt:
  static analysis → secret scan → Firebase probe → S3 bucket enum → IDOR sweep → API surface map
Returns a unified checklist of results.
"""
import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

# job_id → job dict (in-memory)
_jobs: dict[str, dict] = {}

CHECKLIST_STEPS = [
    "static_analysis",
    "secret_scan",
    "firebase_probe",
    "s3_bucket_enum",
    "idor_sweep",
    "api_surface_map",
]


class BugBountyRequest(BaseModel):
    analysis_id: int
    app_name: str = ""
    scope_notes: str = ""


class BugBountyStatus(BaseModel):
    job_id: str
    app_name: str
    status: str  # running | complete | error
    started_at: str
    steps: list[dict]
    error: str | None = None


@router.post("/run", response_model=BugBountyStatus)
async def run_bug_bounty(req: BugBountyRequest):
    """Start a bug bounty recon workflow for an already-analyzed APK/IPA."""
    from database import AsyncSessionLocal
    from models.analysis import Analysis
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Analysis).where(Analysis.id == req.analysis_id))
        analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if analysis.status != "complete":
        raise HTTPException(400, "Analysis must be complete before running a bug bounty sweep")

    job_id = str(uuid.uuid4())[:8]
    steps = [{"name": s, "status": "pending", "result": None, "error": None} for s in CHECKLIST_STEPS]
    job = {
        "job_id": job_id,
        "app_name": req.app_name or analysis.apk_filename,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "steps": steps,
        "error": None,
        "analysis_id": req.analysis_id,
        "analysis": analysis,
    }
    _jobs[job_id] = job

    asyncio.create_task(_run_workflow(job_id))
    return _to_response(job)


@router.get("/{job_id}", response_model=BugBountyStatus)
async def get_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return _to_response(job)


@router.get("", response_model=list[BugBountyStatus])
async def list_jobs():
    return [_to_response(j) for j in _jobs.values()]


def _to_response(job: dict) -> BugBountyStatus:
    return BugBountyStatus(
        job_id=job["job_id"],
        app_name=job["app_name"],
        status=job["status"],
        started_at=job["started_at"],
        steps=job["steps"],
        error=job.get("error"),
    )


def _step(job: dict, name: str) -> dict:
    for s in job["steps"]:
        if s["name"] == name:
            return s
    raise KeyError(name)


async def _run_workflow(job_id: str) -> None:
    job = _jobs[job_id]
    analysis = job["analysis"]
    aid = job["analysis_id"]

    try:
        # 1. Static analysis findings summary
        await _exec_step(job, "static_analysis", _step_static(aid))
        # 2. Secret scan summary (from existing findings)
        await _exec_step(job, "secret_scan", _step_secrets(aid))
        # 3. Firebase probe
        await _exec_step(job, "firebase_probe", _step_firebase(analysis))
        # 4. S3 bucket enum
        await _exec_step(job, "s3_bucket_enum", _step_s3(analysis))
        # 5. IDOR sweep (passive — uses proxy findings)
        await _exec_step(job, "idor_sweep", _step_idor(aid))
        # 6. API surface map
        await _exec_step(job, "api_surface_map", _step_api_surface(aid))

        job["status"] = "complete"
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)


async def _exec_step(job: dict, name: str, coro) -> None:
    s = _step(job, name)
    s["status"] = "running"
    try:
        result = await coro
        s["status"] = "complete"
        s["result"] = result
    except Exception as exc:
        s["status"] = "error"
        s["error"] = str(exc)


# ── Individual step implementations ───────────────────────────────────────────

async def _step_static(analysis_id: int) -> dict:
    from database import AsyncSessionLocal
    from models.analysis import StaticFinding
    from sqlalchemy import select, func
    async with AsyncSessionLocal() as db:
        counts = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            q = select(func.count()).select_from(
                select(StaticFinding).where(
                    StaticFinding.analysis_id == analysis_id,
                    StaticFinding.severity == sev,
                ).subquery()
            )
            counts[sev] = (await db.execute(q)).scalar_one()
    return {"findings_by_severity": counts, "total": sum(counts.values())}


async def _step_secrets(analysis_id: int) -> dict:
    from database import AsyncSessionLocal
    from models.analysis import StaticFinding
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StaticFinding).where(
                StaticFinding.analysis_id == analysis_id,
                StaticFinding.category == "secret",
            )
        )
        findings = result.scalars().all()
    return {
        "count": len(findings),
        "items": [{"title": f.title, "severity": f.severity, "location": f.location} for f in findings[:20]],
    }


async def _step_firebase(analysis) -> dict:
    """Check for Firebase URLs in findings and probe for open read access."""
    from database import AsyncSessionLocal
    from models.analysis import StaticFinding
    from sqlalchemy import select
    import re, httpx
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StaticFinding).where(StaticFinding.analysis_id == analysis.id)
        )
        findings = result.scalars().all()

    firebase_pattern = re.compile(r'https://[\w-]+\.firebaseio\.com', re.IGNORECASE)
    urls: set[str] = set()
    for f in findings:
        if f.evidence:
            for m in firebase_pattern.findall(f.evidence):
                urls.add(m.rstrip("/"))

    results = []
    for url in list(urls)[:5]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{url}/.json")
                results.append({
                    "url": url,
                    "status": r.status_code,
                    "open": r.status_code == 200 and r.text not in ("null", ""),
                })
        except Exception as e:
            results.append({"url": url, "status": None, "error": str(e)})

    return {"databases_found": len(urls), "probed": results}


async def _step_s3(analysis) -> dict:
    """Probe S3 buckets found in static findings."""
    from database import AsyncSessionLocal
    from models.analysis import StaticFinding
    from sqlalchemy import select
    import re, httpx
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StaticFinding).where(StaticFinding.analysis_id == analysis.id)
        )
        findings = result.scalars().all()

    s3_pattern = re.compile(r'[\w-]+\.s3(?:[-.\w]*)?\.amazonaws\.com|s3\.amazonaws\.com/[\w-]+', re.I)
    buckets: set[str] = set()
    for f in findings:
        if f.evidence:
            for m in s3_pattern.findall(f.evidence):
                buckets.add(m)

    results = []
    for bucket in list(buckets)[:5]:
        url = f"https://{bucket}" if not bucket.startswith("http") else bucket
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(url)
                results.append({
                    "bucket": bucket,
                    "status": r.status_code,
                    "public_read": r.status_code == 200,
                })
        except Exception as e:
            results.append({"bucket": bucket, "status": None, "error": str(e)})

    return {"buckets_found": len(buckets), "probed": results}


async def _step_idor(analysis_id: int) -> dict:
    """Summarise IDOR findings from the proxy interceptor."""
    from database import AsyncSessionLocal
    from sqlalchemy import text
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("SELECT COUNT(*) FROM idor_findings WHERE analysis_id = :aid"),
                {"aid": analysis_id},
            )
            count = result.scalar_one()
        return {"idor_findings": count, "note": "Run IDOR sweep from Scanner for full results"}
    except Exception:
        return {"idor_findings": 0, "note": "IDOR table not available — run a proxy-intercepted session first"}


async def _step_api_surface(analysis_id: int) -> dict:
    """Count API endpoints discovered from proxy or decompiled code."""
    from database import AsyncSessionLocal
    from models.analysis import StaticFinding
    from sqlalchemy import select
    import re
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StaticFinding).where(StaticFinding.analysis_id == analysis_id)
        )
        findings = result.scalars().all()

    url_pattern = re.compile(r'https?://[^\s\'"<>]{8,}', re.I)
    endpoints: set[str] = set()
    for f in findings:
        if f.evidence:
            for m in url_pattern.findall(f.evidence):
                endpoints.add(m[:120])

    return {"endpoints_discovered": len(endpoints), "sample": sorted(endpoints)[:10]}
