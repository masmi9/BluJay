import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, AsyncSessionLocal
from models.brute_force import BruteForceJob, BruteForceAttempt
from schemas.brute_force import (
    BruteForceJobCreate, BruteForceJobOut,
    BruteForceAttemptOut, DetectEndpointsRequest,
)

router = APIRouter()

_bf_queues: dict[int, asyncio.Queue] = {}

DEFAULT_WORDLIST = str(__import__("pathlib").Path(__file__).parent.parent / "wordlists" / "top_passwords.txt")


def get_bf_queue(job_id: int) -> asyncio.Queue | None:
    return _bf_queues.get(job_id)


@router.post("/detect", response_model=list[dict])
async def detect_endpoints(body: DetectEndpointsRequest, db: AsyncSession = Depends(get_db)):
    from models.session import ProxyFlow
    from core.brute_forcer import detect_login_endpoints

    result = await db.execute(
        select(ProxyFlow).where(ProxyFlow.session_id == body.session_id)
    )
    flows = result.scalars().all()
    return detect_login_endpoints(flows)


@router.post("/jobs", response_model=BruteForceJobOut, status_code=201)
async def create_job(
    body: BruteForceJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    from core.brute_forcer import run_brute_force_job

    wordlist = body.wordlist_path or DEFAULT_WORDLIST

    job = BruteForceJob(
        target_url=body.target_url,
        auth_type=body.auth_type,
        username_field=body.username_field,
        password_field=body.password_field,
        username=body.username,
        wordlist_path=wordlist,
        concurrency=body.concurrency,
        rate_limit_rps=body.rate_limit_rps,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    queue: asyncio.Queue = asyncio.Queue()
    _bf_queues[job.id] = queue

    async def _run():
        await run_brute_force_job(
            job_id=job.id,
            target_url=body.target_url,
            auth_type=body.auth_type,
            username_field=body.username_field,
            password_field=body.password_field,
            username=body.username,
            wordlist_path=wordlist,
            concurrency=body.concurrency,
            rate_limit_rps=body.rate_limit_rps,
            request_headers={},
            db_factory=AsyncSessionLocal,
            progress_queue=queue,
        )
        _bf_queues.pop(job.id, None)

    background_tasks.add_task(_run)
    return job


@router.post("/jobs/{job_id}/pause", response_model=BruteForceJobOut)
async def pause_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(BruteForceJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != "running":
        raise HTTPException(400, "Job is not running")
    job.status = "paused"
    await db.commit()
    await db.refresh(job)
    return job


@router.post("/jobs/{job_id}/resume", response_model=BruteForceJobOut)
async def resume_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    job = await db.get(BruteForceJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != "paused":
        raise HTTPException(400, "Job is not paused")

    job.status = "running"
    await db.commit()
    await db.refresh(job)

    from core.brute_forcer import run_brute_force_job
    queue: asyncio.Queue = asyncio.Queue()
    _bf_queues[job.id] = queue

    async def _run():
        await run_brute_force_job(
            job_id=job.id,
            target_url=job.target_url,
            auth_type=job.auth_type,
            username_field=job.username_field,
            password_field=job.password_field,
            username=job.username,
            wordlist_path=job.wordlist_path or DEFAULT_WORDLIST,
            concurrency=job.concurrency,
            rate_limit_rps=job.rate_limit_rps,
            request_headers={},
            db_factory=AsyncSessionLocal,
            progress_queue=queue,
        )
        _bf_queues.pop(job.id, None)

    background_tasks.add_task(_run)
    return job


@router.get("/jobs", response_model=list[BruteForceJobOut])
async def list_jobs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BruteForceJob).order_by(BruteForceJob.created_at.desc()))
    return result.scalars().all()


@router.get("/jobs/{job_id}", response_model=BruteForceJobOut)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(BruteForceJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/jobs/{job_id}/attempts", response_model=list[BruteForceAttemptOut])
async def get_attempts(
    job_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    success_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    q = select(BruteForceAttempt).where(BruteForceAttempt.job_id == job_id)
    if success_only:
        q = q.where(BruteForceAttempt.success == True)  # noqa: E712
    q = q.order_by(BruteForceAttempt.id.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    return result.scalars().all()
