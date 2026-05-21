"""
Performance Testing API — Layer 4.

POST /perf/run
  Accepts finding metadata, spawns a Docker k6 container with the appropriate
  test script, and streams results back via WebSocket.

GET  /perf/{job_id}
  Returns current job status.

GET  /perf/jobs
  Lists all perf jobs in this session.

WebSocket: /ws/perf/{job_id}
  Streams {"type": "progress"|"metric"|"done"|"error", ...} events.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from core.perf_runner import run_k6

logger = structlog.get_logger()
router = APIRouter()

# ── In-memory job store ────────────────────────────────────────────────────────
_jobs: dict[str, dict[str, Any]] = {}
_job_queues: dict[str, asyncio.Queue] = {}


# ── Schemas ────────────────────────────────────────────────────────────────────

class PerfRunRequest(BaseModel):
    target_url: str
    finding_type: str           # race_condition | auth_endpoint | idor_found | api_endpoint | slow_response
    vus: int = 10               # virtual users
    duration: str = "30s"       # k6 duration string e.g. "30s", "2m"
    extra_env: dict[str, str] = {}


class PerfJobStatus(BaseModel):
    job_id: str
    status: str                 # running | completed | failed
    finding_type: str
    target_url: str
    script: str | None
    started_at: str
    finished_at: str | None
    exit_code: int | None
    error: str | None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_job_or_404(job_id: str) -> dict:
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Perf job {job_id!r} not found")
    return job


def _job_to_status(job_id: str, job: dict) -> PerfJobStatus:
    return PerfJobStatus(
        job_id=job_id,
        status=job["status"],
        finding_type=job["finding_type"],
        target_url=job["target_url"],
        script=job.get("script"),
        started_at=job["started_at"],
        finished_at=job.get("finished_at"),
        exit_code=job.get("exit_code"),
        error=job.get("error"),
    )


# ── Background task ────────────────────────────────────────────────────────────

async def _run_job(job_id: str, req: PerfRunRequest) -> None:
    job = _jobs[job_id]
    queue = _job_queues[job_id]

    await run_k6(
        job_id=job_id,
        target_url=req.target_url,
        finding_type=req.finding_type,
        queue=queue,
        vus=req.vus,
        duration=req.duration,
        extra_env=req.extra_env,
    )

    # Drain the queue to capture final event
    done_event: dict | None = None
    while not queue.empty():
        evt = queue.get_nowait()
        if evt.get("type") == "done":
            done_event = evt
        elif evt.get("type") == "error":
            job["status"] = "failed"
            job["error"] = evt.get("message")
            job["finished_at"] = datetime.now(timezone.utc).isoformat()

    if done_event:
        job["status"] = "completed"
        job["exit_code"] = done_event.get("exit_code")
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
    elif job["status"] != "failed":
        job["status"] = "completed"
        job["finished_at"] = datetime.now(timezone.utc).isoformat()


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/run", response_model=PerfJobStatus)
async def run_perf_test(body: PerfRunRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    _jobs[job_id] = {
        "status": "running",
        "finding_type": body.finding_type,
        "target_url": body.target_url,
        "script": None,
        "started_at": now,
        "finished_at": None,
        "exit_code": None,
        "error": None,
    }
    _job_queues[job_id] = asyncio.Queue(maxsize=2000)

    background_tasks.add_task(_run_job, job_id, body)
    logger.info("perf job started", job_id=job_id, finding_type=body.finding_type, target=body.target_url)

    return _job_to_status(job_id, _jobs[job_id])


@router.get("/jobs", response_model=list[PerfJobStatus])
async def list_perf_jobs():
    return [_job_to_status(jid, j) for jid, j in _jobs.items()]


@router.get("/{job_id}", response_model=PerfJobStatus)
async def get_perf_job(job_id: str):
    return _job_to_status(job_id, _get_job_or_404(job_id))


def get_perf_queue(job_id: str) -> asyncio.Queue | None:
    return _job_queues.get(job_id)
