"""
LangGraph Pipeline API — Layer 2.

Endpoints:
  POST   /pipeline/run                 start a new pipeline run
  GET    /pipeline/{run_id}            get run status + results
  POST   /pipeline/{run_id}/resume     resume after human gate
  GET    /pipeline/runs                list all runs

WebSocket:
  /ws/pipeline/{run_id}                stream real-time node events

Run lifecycle:
  running → awaiting_review → (approved) running → completed
                             → (denied)  denied
  running → failed  (on unhandled exception)
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from agents.graph import graph
from agents.state import AgentState
from langgraph.types import Command

logger = structlog.get_logger()
router = APIRouter()

# ── In-memory run store ────────────────────────────────────────────────────────
# Structure: { run_id: { status, state_snapshot, gate_payload, events_queue, started_at, finished_at } }
_runs: dict[str, dict[str, Any]] = {}
_queues: dict[str, asyncio.Queue] = {}  # for WebSocket streaming


# ── Schemas ────────────────────────────────────────────────────────────────────

class StartPipelineRequest(BaseModel):
    target_url: str
    scan_type: str = "web"          # "web" | "api"
    session_id: int | None = None


class ResumeRequest(BaseModel):
    decision: str                   # "approved" | "denied"


class RunSummary(BaseModel):
    run_id: str
    status: str
    target_url: str
    scan_type: str
    finding_count: int
    gate_payload: dict | None
    report_summary: str | None
    started_at: str
    finished_at: str | None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_run_or_404(run_id: str) -> dict:
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Pipeline run {run_id!r} not found")
    return run


def _make_summary(run_id: str, run: dict) -> RunSummary:
    snap = run.get("state_snapshot") or {}
    findings = snap.get("exploit_findings") or snap.get("validated_findings") or []
    return RunSummary(
        run_id=run_id,
        status=run["status"],
        target_url=run["target_url"],
        scan_type=run["scan_type"],
        finding_count=len(findings),
        gate_payload=run.get("gate_payload"),
        report_summary=snap.get("report_summary"),
        started_at=run["started_at"],
        finished_at=run.get("finished_at"),
    )


async def _emit(run_id: str, msg: dict) -> None:
    q = _queues.get(run_id)
    if q:
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


# ── Background pipeline runner ────────────────────────────────────────────────

async def _run_pipeline(run_id: str, initial_state: AgentState) -> None:
    config = {"configurable": {"thread_id": run_id}}
    run = _runs[run_id]

    try:
        async for event in graph.astream(initial_state, config=config, stream_mode="updates"):
            # Check for human-gate interrupt
            if "__interrupt__" in event:
                interrupt_obj = event["__interrupt__"]
                gate_payload = interrupt_obj[0].value if interrupt_obj else {}
                run["status"] = "awaiting_review"
                run["gate_payload"] = gate_payload
                await _emit(run_id, {"type": "interrupt", "data": gate_payload})
                logger.info("pipeline paused at gate", run_id=run_id)
                return  # background task exits; resume creates a new one

            # Normal node update
            for node_name, delta in event.items():
                if node_name.startswith("__"):
                    continue
                run["state_snapshot"] = {**(run.get("state_snapshot") or {}), **delta}
                await _emit(run_id, {"type": "node_update", "node": node_name, "delta": delta})
                logger.info("pipeline node done", run_id=run_id, node=node_name)

        run["status"] = "completed"
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        await _emit(run_id, {"type": "done", "run_id": run_id})

    except Exception as exc:
        run["status"] = "failed"
        run["error"] = str(exc)
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        await _emit(run_id, {"type": "error", "message": str(exc)})
        logger.error("pipeline failed", run_id=run_id, error=str(exc))


async def _resume_pipeline(run_id: str, decision: str) -> None:
    config = {"configurable": {"thread_id": run_id}}
    run = _runs[run_id]
    run["status"] = "running"

    try:
        async for event in graph.astream(
            Command(resume=decision), config=config, stream_mode="updates"
        ):
            if "__interrupt__" in event:
                # Shouldn't happen post-gate, but handle defensively
                run["status"] = "awaiting_review"
                run["gate_payload"] = event["__interrupt__"][0].value if event["__interrupt__"] else {}
                await _emit(run_id, {"type": "interrupt", "data": run["gate_payload"]})
                return

            for node_name, delta in event.items():
                if node_name.startswith("__"):
                    continue
                run["state_snapshot"] = {**(run.get("state_snapshot") or {}), **delta}
                await _emit(run_id, {"type": "node_update", "node": node_name, "delta": delta})

        run["status"] = "completed"
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        await _emit(run_id, {"type": "done", "run_id": run_id})

    except Exception as exc:
        run["status"] = "failed"
        run["error"] = str(exc)
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        await _emit(run_id, {"type": "error", "message": str(exc)})
        logger.error("pipeline resume failed", run_id=run_id, error=str(exc))


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/run", response_model=RunSummary)
async def start_pipeline(body: StartPipelineRequest, background_tasks: BackgroundTasks):
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    initial_state: AgentState = {
        "run_id": run_id,
        "target_url": body.target_url,
        "scan_type": body.scan_type,
        "session_id": body.session_id,
        "recon_results": [],
        "exploit_findings": [],
        "variant_iterations": 0,
        "validated_findings": [],
        "report_sarif": {},
        "report_summary": "",
        "gate_decision": None,
        "gate_summary": "",
        "messages": [],
        "status": "running",
        "error": None,
    }

    _runs[run_id] = {
        "status": "running",
        "target_url": body.target_url,
        "scan_type": body.scan_type,
        "state_snapshot": None,
        "gate_payload": None,
        "started_at": now,
        "finished_at": None,
    }
    _queues[run_id] = asyncio.Queue(maxsize=1000)

    background_tasks.add_task(_run_pipeline, run_id, initial_state)
    logger.info("pipeline started", run_id=run_id, target=body.target_url)

    return _make_summary(run_id, _runs[run_id])


@router.get("/runs", response_model=list[RunSummary])
async def list_runs():
    return [_make_summary(rid, run) for rid, run in _runs.items()]


@router.get("/{run_id}", response_model=RunSummary)
async def get_run(run_id: str):
    return _make_summary(run_id, _get_run_or_404(run_id))


@router.post("/{run_id}/resume", response_model=RunSummary)
async def resume_pipeline(run_id: str, body: ResumeRequest, background_tasks: BackgroundTasks):
    run = _get_run_or_404(run_id)

    if run["status"] != "awaiting_review":
        raise HTTPException(
            status_code=409,
            detail=f"Run {run_id!r} is not awaiting review (status={run['status']!r})",
        )

    if body.decision not in ("approved", "denied"):
        raise HTTPException(status_code=422, detail="decision must be 'approved' or 'denied'")

    if run_id not in _queues:
        _queues[run_id] = asyncio.Queue(maxsize=1000)

    background_tasks.add_task(_resume_pipeline, run_id, body.decision)
    logger.info("pipeline resumed", run_id=run_id, decision=body.decision)

    return _make_summary(run_id, run)


def get_pipeline_queue(run_id: str) -> asyncio.Queue | None:
    return _queues.get(run_id)
