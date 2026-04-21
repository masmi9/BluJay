import asyncio
import json
import re

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, AsyncSessionLocal
from models.fuzzing import FuzzJob, FuzzResult
from schemas.fuzzing import FuzzJobCreate, FuzzJobOut, FuzzResultOut, FuzzJobDetail

router = APIRouter()

_fuzz_queues: dict[int, asyncio.Queue] = {}


def get_fuzz_queue(job_id: int) -> asyncio.Queue | None:
    return _fuzz_queues.get(job_id)


@router.post("/jobs", response_model=FuzzJobOut, status_code=201)
async def create_job(
    body: FuzzJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    from core.api_fuzzer import (
        extract_endpoints_from_flows,
        extract_endpoints_from_static,
        run_fuzz_job,
    )

    specs = []

    # From proxy flows
    if body.session_id:
        from models.session import ProxyFlow
        result = await db.execute(
            select(ProxyFlow).where(ProxyFlow.session_id == body.session_id)
        )
        flows = result.scalars().all()
        specs.extend(extract_endpoints_from_flows(flows))

    # From static analysis
    if body.analysis_id:
        from models.analysis import Analysis
        analysis = await db.get(Analysis, body.analysis_id)
        if analysis and analysis.jadx_path:
            specs.extend(extract_endpoints_from_static(analysis.jadx_path, body.base_url))

    # Filter
    if body.endpoint_filter:
        pat = re.compile(body.endpoint_filter, re.IGNORECASE)
        specs = [s for s in specs if pat.search(s.url)]

    job = FuzzJob(
        session_id=body.session_id,
        analysis_id=body.analysis_id,
        attacks=json.dumps(body.attacks),
        endpoint_count=len(specs),
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    queue: asyncio.Queue = asyncio.Queue()
    _fuzz_queues[job.id] = queue

    async def _run():
        await run_fuzz_job(job.id, specs, body.attacks, AsyncSessionLocal, queue)
        _fuzz_queues.pop(job.id, None)

    background_tasks.add_task(_run)
    return job


@router.get("/jobs", response_model=list[FuzzJobOut])
async def list_jobs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FuzzJob).order_by(FuzzJob.created_at.desc()))
    return result.scalars().all()


@router.get("/jobs/{job_id}", response_model=FuzzJobDetail)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(FuzzJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    result = await db.execute(
        select(FuzzResult).where(FuzzResult.job_id == job_id).order_by(FuzzResult.is_interesting.desc())
    )
    results = result.scalars().all()
    return FuzzJobDetail(
        **{c.key: getattr(job, c.key) for c in job.__table__.columns},
        results=[FuzzResultOut.model_validate(r) for r in results],
    )


@router.delete("/jobs/{job_id}", status_code=204)
async def delete_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(FuzzJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    await db.delete(job)
    await db.commit()
