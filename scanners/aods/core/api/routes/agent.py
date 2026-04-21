"""
AODS Agent Intelligence API Routes
====================================

Provides API endpoints for the optional AI agent system (Track 90).

Endpoints:
- POST /api/agent/tasks          - Start a new agent task
- GET  /api/agent/tasks          - List agent tasks
- GET  /api/agent/tasks/{id}     - Get task details
- POST /api/agent/tasks/{id}/cancel - Cancel a running task
- GET  /api/agent/tasks/{id}/stream - SSE observation stream
- GET  /api/agent/tasks/{id}/transcript - Get full transcript
- GET  /api/agent/config         - Get agent config (admin only)
- GET  /api/agent/triage/feedback/export - Export triage feedback from reports

Security:
- All endpoints require authentication
- RBAC enforced: admin and analyst roles
- Returns 503 if agent system is disabled
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from core.api.shared_state import (
    check_expensive_op_rate,
    acquire_agent_slot,
    release_agent_slot,
)

try:
    from core.logging_config import get_logger

    logger = get_logger(__name__)
except ImportError:
    import logging as stdlib_logging

    logger = stdlib_logging.getLogger(__name__)


router = APIRouter(prefix="/agent", tags=["agent"])

# ---------------------------------------------------------------------------
# Safe path roots - file paths in requests must resolve under one of these
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SAFE_ROOTS = [_REPO_ROOT, Path("/tmp")]


def _validate_safe_path(p: str) -> Path:
    """Validate that a user-supplied file path is safe (no traversal).

    Rejects paths containing '..', and ensures the resolved path lives
    under the repo root or /tmp.  Raises HTTPException(400) on violation.
    """
    if ".." in p:
        raise HTTPException(status_code=400, detail="Path traversal not allowed")
    resolved = Path(p).resolve()
    for root in _SAFE_ROOTS:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise HTTPException(
        status_code=400,
        detail="Path must be under the project root or /tmp",
    )


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class StartAgentTaskRequest(BaseModel):
    """Request to start a new agent task."""

    model_config = ConfigDict(extra="forbid")

    agent_type: str = Field(
        ...,
        description="Agent type: analyze, narrate, verify, orchestrate, triage, remediate, pipeline",
        pattern="^(analyze|narrate|verify|orchestrate|triage|remediate|pipeline)$",
    )
    scan_id: Optional[str] = Field(None, max_length=200, description="Scan session ID to analyze")
    report_file: Optional[str] = Field(None, min_length=1, max_length=1024, description="Report file to analyze")
    prompt: Optional[str] = Field(None, max_length=5000, description="Custom prompt override")
    params: Optional[Dict[str, Any]] = Field(None, description="Additional agent parameters")


class NarrateRequest(BaseModel):
    """Convenience request for narration agent."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report to narrate")
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class VerifyRequest(BaseModel):
    """Convenience request for verification agent."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report to verify")
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class OrchestrateRequest(BaseModel):
    """Convenience request for orchestration agent."""

    model_config = ConfigDict(extra="forbid")

    apk_path: str = Field(
        ..., min_length=1, max_length=1024, description="APK file path to orchestrate plugins for"
    )
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class TriageRequest(BaseModel):
    """Convenience request for triage agent."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report to triage")
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class RemediateRequest(BaseModel):
    """Convenience request for remediation agent."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(
        ..., min_length=1, max_length=1024, description="Path to the JSON scan report to remediate"
    )
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class StartPipelineRequest(BaseModel):
    """Request to start an agent pipeline."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report")
    steps: Optional[list] = Field(
        None,
        description="Pipeline steps to run (default: triage,verify,remediate,narrate)",
    )
    total_token_budget: int = Field(200000, description="Total token budget across all steps")
    stop_on_failure: bool = Field(False, description="Stop pipeline on first step failure")
    scan_id: Optional[str] = Field(None, max_length=200, description="Optional scan session ID")


class TriageFeedbackRequest(BaseModel):
    """Request to submit analyst feedback on a triage classification."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report")
    finding_title: str = Field(..., min_length=1, max_length=500, description="Title of the finding being reviewed")
    action: str = Field(..., description="accept or reject", pattern="^(accept|reject)$")
    new_classification: Optional[str] = Field(None, max_length=200, description="New classification if rejecting")
    reason: Optional[str] = Field(None, max_length=2000, description="Reason for the feedback")


class AgentFeedbackRequest(BaseModel):
    """Request to submit feedback on any agent output."""

    model_config = ConfigDict(extra="forbid")

    report_file: str = Field(..., min_length=1, max_length=1024, description="Path to the JSON scan report")
    agent_type: str = Field(
        ..., pattern=r"^(narrate|verify|triage|remediate|orchestrate)$",
        description="Agent type that produced the output",
    )
    item_title: str = Field(..., min_length=1, max_length=512, description="Title of the item being reviewed")
    action: str = Field(
        ..., pattern=r"^(helpful|unhelpful|incorrect)$",
        description="Feedback action: helpful, unhelpful, or incorrect",
    )
    reason: Optional[str] = Field(None, max_length=1000, description="Reason for the feedback")
    correction: Optional[str] = Field(None, max_length=2000, description="Corrected value if applicable")


class AgentTaskResponse(BaseModel):
    """Response for a single agent task."""

    model_config = ConfigDict(extra="forbid")

    id: str
    agent_type: str
    scan_id: Optional[str] = None
    user: Optional[str] = None
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    iterations: int = 0
    token_usage: Dict[str, int] = Field(default_factory=dict)
    result: Optional[str] = None
    error: Optional[str] = None
    observations_count: int = 0


class UpdateAgentConfigRequest(BaseModel):
    """Request to update agent configuration at runtime."""

    model_config = ConfigDict(extra="forbid")

    enabled: Optional[bool] = Field(None, description="Enable/disable agent system")
    provider: Optional[str] = Field(
        None,
        pattern="^(anthropic|openai|ollama)$",
        description="LLM provider: anthropic, openai, or ollama",
    )
    model: Optional[str] = Field(None, max_length=200, description="Override LLM model")
    max_iterations: Optional[int] = Field(None, ge=1, le=200, description="Override max iterations")
    max_wall_time_seconds: Optional[int] = Field(None, ge=10, le=3600, description="Override wall time")
    cost_limit_usd: Optional[float] = Field(None, ge=0.01, le=100.0, description="Override cost limit")


class AgentConfigResponse(BaseModel):
    """Response showing agent configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    provider: str
    model: str
    budget: Dict[str, Any]
    agents: Dict[str, Any]


class TriageFeedbackHistoryItem(BaseModel):
    """A single historical triage feedback entry."""

    model_config = ConfigDict(extra="forbid")

    finding_title: str = ""
    action: str = ""
    new_classification: str = ""
    reason: str = ""
    user: str = ""
    timestamp: str = ""
    scan_id: str = ""
    similarity_score: float = 0.0


class TriageFeedbackHistoryResponse(BaseModel):
    """Response for triage feedback history query."""

    model_config = ConfigDict(extra="forbid")

    results: List[TriageFeedbackHistoryItem] = Field(default_factory=list)
    total: int = 0
    vector_db_available: bool = False


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------


def _get_auth_helpers():
    """Import auth helpers."""
    from core.api.auth_helpers import _require_roles, _get_user_info

    return _require_roles, _get_user_info


def _check_agent_enabled() -> None:
    """Raise 503 if agent system is not enabled."""
    if os.environ.get("AODS_AGENT_ENABLED", "0").lower() not in ("1", "true", "yes"):
        raise HTTPException(
            status_code=503,
            detail="Agent system is disabled. Set AODS_AGENT_ENABLED=1 to enable.",
        )


def _get_agent_config():
    """Load and return agent config."""
    from core.agent.config import load_agent_config

    return load_agent_config()


def _store_triage_feedback_vector(
    body: "TriageFeedbackRequest",
    username: str,
    report_file: str = "",
) -> None:
    """Best-effort store of triage feedback in vector DB for future queries."""
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return
    try:
        from core.vector_db.chromadb_backend import get_chromadb_backend
        from core.vector_db.embedder import compute_finding_embedding

        text_for_embedding = (
            f"{body.finding_title} {body.action} "
            f"{body.new_classification or ''} {body.reason or ''}"
        )
        finding_stub = {"title": text_for_embedding, "description": body.reason or ""}
        embedding = compute_finding_embedding(finding_stub)
        if embedding is None:
            return

        backend = get_chromadb_backend()
        # Stable hash for deterministic doc IDs across restarts
        id_input = f"{body.finding_title}:{username}".encode("utf-8")
        doc_id = f"triage-feedback-{hashlib.sha256(id_input).hexdigest()[:16]}"

        # Extract scan_id from report for traceability
        scan_id = ""
        if report_file:
            try:
                with open(report_file, "r") as f:
                    rdata = json.load(f)
                scan_id = rdata.get("session_id") or rdata.get("scan_id", "")
            except Exception:
                pass

        metadata = {
            "type": "triage_feedback",
            "finding_title": body.finding_title[:200],
            "action": body.action,
            "new_classification": body.new_classification or "",
            "reason": (body.reason or "")[:500],
            "user": username,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Required ownership fields
            "scan_id": scan_id,
            "owner_user_id": username,
            "tenant_id": "default",
            "visibility": "shared",
            "report_file": str(report_file)[:300],
        }
        backend.index(doc_id, embedding, metadata)
        logger.debug("triage_feedback_vectorized", finding=body.finding_title[:50])
    except Exception as exc:
        logger.debug("triage_feedback_vector_failed", error=str(exc))


def _task_to_response(task: Dict[str, Any]) -> AgentTaskResponse:
    """Convert internal task dict to API response model."""
    return AgentTaskResponse(
        id=task["id"],
        agent_type=task["agent_type"],
        scan_id=task.get("scan_id"),
        user=task.get("user"),
        status=task["status"],
        created_at=task["created_at"],
        started_at=task.get("started_at"),
        completed_at=task.get("completed_at"),
        iterations=task.get("iterations", 0),
        token_usage=task.get("token_usage", {}),
        result=task.get("result"),
        error=task.get("error"),
        observations_count=len(task.get("observations", [])),
    )


def _build_user_message(req: StartAgentTaskRequest) -> str:
    """Build the initial user message for the agent."""
    if req.prompt:
        return req.prompt

    messages = {
        "analyze": (
            "Analyze the scan results comprehensively. Identify patterns, "
            "correlate findings, and provide actionable insights."
        ),
        "narrate": (
            "Summarize the scan findings in clear, natural language suitable "
            "for a security report. Focus on the most impactful vulnerabilities."
        ),
        "verify": (
            "Verify the HIGH and CRITICAL findings from the scan report using "
            "dynamic analysis. Check Frida availability, generate verification "
            "scripts, and update finding confidence based on evidence."
        ),
        "orchestrate": (
            "Analyze the APK and select the optimal set of security analysis "
            "plugins to run. Use analyze_manifest, detect_libraries, and "
            "get_plugin_catalog tools, then produce an orchestration plan."
        ),
        "triage": (
            "Triage the scan findings by exploitability, impact, and remediation "
            "effort. Provide a prioritized list with recommended actions."
        ),
        "remediate": (
            "Generate concrete code patches for the vulnerability findings. "
            "Provide before/after code snippets with explanations and difficulty estimates."
        ),
    }
    base = messages.get(req.agent_type, f"Perform {req.agent_type} analysis on the scan results.")

    if req.report_file:
        base += f" The report file is: {req.report_file}"
    if req.scan_id:
        base += f" The scan session ID is: {req.scan_id}"

    return base


def _run_agent_background(
    task_id: str, config, agent_type: str, user_message: str, tool_context, report_file: Optional[str] = None
):
    """Run agent loop in a background thread.

    For narrate agent type, delegates to run_narration_background() which
    adds structured Narrative parsing and report integration.
    """
    from core.agent.state import update_agent_task

    # Narrate agent: use specialized runner with structured output
    if agent_type == "narrate":
        try:
            from core.agent.narration import run_narration_background

            run_narration_background(
                task_id=task_id,
                config=config,
                user_message=user_message,
                tool_context=tool_context,
                report_file=report_file,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    # Verify agent: use specialized runner with structured output
    if agent_type == "verify":
        try:
            from core.agent.verification import run_verification_background

            run_verification_background(
                task_id=task_id,
                config=config,
                user_message=user_message,
                tool_context=tool_context,
                report_file=report_file,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    # Orchestrate agent: use specialized runner with structured output
    if agent_type == "orchestrate":
        try:
            from core.agent.orchestration import run_orchestration_background

            run_orchestration_background(
                task_id=task_id,
                config=config,
                user_message=user_message,
                tool_context=tool_context,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    # Triage agent: use specialized runner with structured output
    if agent_type == "triage":
        try:
            from core.agent.triage import run_triage_background

            run_triage_background(
                task_id=task_id,
                config=config,
                user_message=user_message,
                tool_context=tool_context,
                report_file=report_file,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    # Remediate agent: use specialized runner with structured output
    if agent_type == "remediate":
        try:
            from core.agent.remediation import run_remediation_background

            run_remediation_background(
                task_id=task_id,
                config=config,
                user_message=user_message,
                tool_context=tool_context,
                report_file=report_file,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    # Pipeline: run supervisor pipeline in background
    if agent_type == "pipeline":
        try:
            from core.agent.supervisor import run_pipeline_background

            run_pipeline_background(
                task_id=task_id,
                config=config,
                report_file=report_file,
            )
            return
        except ImportError:
            pass  # Fall through to generic loop

    try:
        from core.agent.loop import AgentLoop

        loop = AgentLoop(
            config=config,
            agent_type=agent_type,
            task_id=task_id,
            tool_context=tool_context,
        )
        result = loop.run(user_message)

        update_agent_task(
            task_id,
            status="completed" if result.success else "failed",
            result=result.response if result.success else None,
            error=result.error,
        )
    except ImportError as e:
        update_agent_task(task_id, status="failed", error=f"Missing dependency: {e}")
    except Exception as e:
        logger.error("agent_task_failed", task_id=task_id, error_type=type(e).__name__)
        update_agent_task(task_id, status="failed", error=type(e).__name__)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/tasks")
def start_agent_task(
    body: StartAgentTaskRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Start a new agent analysis task."""
    _check_agent_enabled()
    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])
    username = user_info.get("user", "unknown")

    check_expensive_op_rate("agent_task", username)
    acquire_agent_slot(username)

    from core.agent.state import create_agent_task
    from core.agent.tools.base import ToolContext

    config = _get_agent_config()
    task_id = create_agent_task(
        agent_type=body.agent_type,
        scan_id=body.scan_id,
        user=username,
        params=body.params,
    )

    # Validate file paths if provided
    if body.report_file:
        _validate_safe_path(body.report_file)

    user_message = _build_user_message(body)
    tool_context = ToolContext(
        scan_id=body.scan_id,
        report_dir="reports",
    )

    def _agent_with_slot_release(*args, **kwargs):
        try:
            _run_agent_background(*args, **kwargs)
        finally:
            release_agent_slot(username)

    # Run in background thread
    thread = threading.Thread(
        target=_agent_with_slot_release,
        args=(task_id, config, body.agent_type, user_message, tool_context),
        kwargs={"report_file": body.report_file},
        daemon=True,
        name=f"agent-{task_id[:8]}",
    )
    thread.start()

    logger.info("agent_task_started", task_id=task_id, agent_type=body.agent_type, user=username)
    return {"task_id": task_id, "status": "pending", "agent_type": body.agent_type}


@router.post("/narrate")
def start_narration(
    body: NarrateRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Convenience endpoint to start a narration agent task.

    Equivalent to POST /agent/tasks with agent_type="narrate".
    """
    task_body = StartAgentTaskRequest(
        agent_type="narrate",
        report_file=body.report_file,
        scan_id=body.scan_id,
    )
    return start_agent_task(task_body, authorization=authorization)


@router.post("/verify")
def start_verification(
    body: VerifyRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Convenience endpoint to start a verification agent task.

    Equivalent to POST /agent/tasks with agent_type="verify".
    """
    task_body = StartAgentTaskRequest(
        agent_type="verify",
        report_file=body.report_file,
        scan_id=body.scan_id,
    )
    return start_agent_task(task_body, authorization=authorization)


@router.post("/orchestrate")
def start_orchestration(
    body: OrchestrateRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Convenience endpoint to start an orchestration agent task.

    Equivalent to POST /agent/tasks with agent_type="orchestrate".
    """
    _validate_safe_path(body.apk_path)
    task_body = StartAgentTaskRequest(
        agent_type="orchestrate",
        scan_id=body.scan_id,
        prompt=f"Analyze the APK at {body.apk_path} and select the optimal set of security "
               f"analysis plugins to run. Use analyze_manifest, detect_libraries, and "
               f"get_plugin_catalog tools, then produce an orchestration plan.",
        params={"apk_path": body.apk_path},
    )
    return start_agent_task(task_body, authorization=authorization)


@router.post("/triage")
def start_triage(
    body: TriageRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Convenience endpoint to start a triage agent task.

    Equivalent to POST /agent/tasks with agent_type="triage".
    """
    task_body = StartAgentTaskRequest(
        agent_type="triage",
        report_file=body.report_file,
        scan_id=body.scan_id,
    )
    return start_agent_task(task_body, authorization=authorization)


@router.post("/remediate")
def start_remediation(
    body: RemediateRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Convenience endpoint to start a remediation agent task.

    Equivalent to POST /agent/tasks with agent_type="remediate".
    """
    task_body = StartAgentTaskRequest(
        agent_type="remediate",
        report_file=body.report_file,
        scan_id=body.scan_id,
    )
    return start_agent_task(task_body, authorization=authorization)


@router.post("/pipeline")
def start_pipeline(
    body: StartPipelineRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Start an agent pipeline that runs multiple agents in sequence.

    Default pipeline: triage -> verify -> remediate -> narrate
    """
    _check_agent_enabled()
    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])
    username = user_info.get("user", "unknown")

    check_expensive_op_rate("agent_pipeline", username)
    acquire_agent_slot(username)

    from core.agent.state import create_agent_task
    from core.agent.tools.base import ToolContext

    # Validate file path
    _validate_safe_path(body.report_file)

    config = _get_agent_config()
    task_id = create_agent_task(
        agent_type="pipeline",
        scan_id=body.scan_id,
        user=username,
        params={"report_file": body.report_file, "steps": body.steps},
    )

    tool_context = ToolContext(
        scan_id=body.scan_id,
        report_dir="reports",
    )

    def _pipeline_with_slot_release(*args, **kwargs):
        try:
            _run_agent_background(*args, **kwargs)
        finally:
            release_agent_slot(username)

    thread = threading.Thread(
        target=_pipeline_with_slot_release,
        args=(task_id, config, "pipeline", "", tool_context),
        kwargs={"report_file": body.report_file},
        daemon=True,
        name=f"pipeline-{task_id[:8]}",
    )
    thread.start()

    logger.info("pipeline_started", task_id=task_id, user=username)
    return {"task_id": task_id, "status": "pending", "agent_type": "pipeline"}


@router.post("/triage/feedback")
def submit_triage_feedback(
    body: TriageFeedbackRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Submit analyst feedback on a triage classification.

    Stores corrections in report["triage_feedback"] without modifying
    the original triage classifications.
    """
    _check_agent_enabled()
    _require_roles, _ = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])
    username = user_info.get("user", "unknown")

    rp = _validate_safe_path(body.report_file)
    if not rp.exists():
        raise HTTPException(status_code=404, detail="report not found")

    try:
        with open(rp, "r") as f:
            report_data = json.load(f)
    except (json.JSONDecodeError, OSError):
        raise HTTPException(status_code=400, detail="Failed to read report")

    feedback_list = report_data.get("triage_feedback", [])
    feedback_list.append({
        "finding_title": body.finding_title,
        "action": body.action,
        "new_classification": body.new_classification,
        "reason": body.reason,
        "user": username,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    report_data["triage_feedback"] = feedback_list

    tmp_path = str(rp) + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        os.rename(tmp_path, str(rp))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="Failed to save feedback")

    # Persist to vector DB for future triage similarity queries
    _store_triage_feedback_vector(body, username, report_file=body.report_file)

    logger.info("triage_feedback_saved", finding=body.finding_title, action=body.action, user=username)
    return {"status": "saved", "finding_title": body.finding_title, "action": body.action}


@router.post("/feedback")
def submit_agent_feedback(
    body: AgentFeedbackRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Submit feedback on any agent output (narration, verification, remediation, etc.).

    Stores feedback in report["{agent_type}_feedback"] and persists to
    vector DB for future few-shot injection.
    """
    _check_agent_enabled()
    _require_roles, _ = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])
    username = user_info.get("user", "unknown")

    rp = _validate_safe_path(body.report_file)
    if not rp.exists():
        raise HTTPException(status_code=404, detail="report not found")

    try:
        with open(rp, "r") as f:
            report_data = json.load(f)
    except (json.JSONDecodeError, OSError):
        raise HTTPException(status_code=400, detail="Failed to read report")

    feedback_key = f"{body.agent_type}_feedback"
    feedback_list = report_data.get(feedback_key, [])
    feedback_entry = {
        "item_title": body.item_title,
        "action": body.action,
        "reason": body.reason,
        "correction": body.correction,
        "user": username,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    feedback_list.append(feedback_entry)
    report_data[feedback_key] = feedback_list

    tmp_path = str(rp) + ".tmp"
    try:
        with open(tmp_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        os.rename(tmp_path, str(rp))
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="Failed to save feedback")

    # Persist to vector DB for future few-shot injection
    _store_generic_feedback_vector(body, username)

    logger.info(
        "agent_feedback_saved",
        agent_type=body.agent_type,
        item=body.item_title,
        action=body.action,
        user=username,
    )
    return {
        "status": "saved",
        "agent_type": body.agent_type,
        "item_title": body.item_title,
        "action": body.action,
    }


def _store_generic_feedback_vector(body: AgentFeedbackRequest, username: str) -> None:
    """Best-effort: persist agent feedback to vector DB for future few-shot injection."""
    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return
    try:
        from core.vector_db import get_semantic_finding_index
        import hashlib

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return

        # Build embedding text from feedback content
        text_parts = [body.item_title, body.action]
        if body.reason:
            text_parts.append(body.reason)

        hash_input = f"{body.item_title}:{username}".encode()
        doc_id = f"{body.agent_type}-feedback-{hashlib.sha256(hash_input).hexdigest()[:16]}"
        metadata = {
            "type": f"{body.agent_type}_feedback",
            "item_title": body.item_title,
            "action": body.action,
            "reason": (body.reason or "")[:500],
            "correction": (body.correction or "")[:500],
            "user": username,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        idx.add_documents(
            documents=[" ".join(text_parts)],
            metadatas=[metadata],
            ids=[doc_id],
        )
    except Exception as exc:
        logger.debug("generic_feedback_vector_store_failed", error=str(exc))


@router.get("/tasks")
def list_tasks(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    authorization: Optional[str] = Header(default=None),
):
    """List agent tasks."""
    _check_agent_enabled()
    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])

    from core.agent.state import list_agent_tasks

    # Analysts see only their own tasks; admins see all
    user_filter = None
    if "admin" not in user_info.get("roles", []):
        user_filter = user_info.get("user")

    tasks = list_agent_tasks(user=user_filter, status=status, limit=limit)
    return {"tasks": [_task_to_response(t) for t in tasks], "count": len(tasks)}


@router.get("/tasks/{task_id}")
def get_task(
    task_id: str,
    authorization: Optional[str] = Header(default=None),
):
    """Get details of a specific agent task."""
    _check_agent_enabled()
    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])

    from core.agent.state import get_agent_task

    task = get_agent_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="agent task not found")

    # Ownership check for non-admins
    if "admin" not in user_info.get("roles", []):
        if task.get("user") != user_info.get("user"):
            raise HTTPException(status_code=403, detail="Access denied")

    return _task_to_response(task)


@router.post("/tasks/{task_id}/cancel")
def cancel_task(
    task_id: str,
    authorization: Optional[str] = Header(default=None),
):
    """Cancel a running agent task."""
    _check_agent_enabled()
    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])

    from core.agent.state import cancel_agent_task, get_agent_task

    task = get_agent_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="agent task not found")

    if "admin" not in user_info.get("roles", []):
        if task.get("user") != user_info.get("user"):
            raise HTTPException(status_code=403, detail="Access denied")

    cancelled = cancel_agent_task(task_id)
    if not cancelled:
        raise HTTPException(status_code=409, detail="Task cannot be cancelled (already terminal)")

    return {"task_id": task_id, "status": "cancelled"}


@router.get("/tasks/{task_id}/stream")
def task_observation_stream(
    task_id: str,
    authorization: Optional[str] = Header(default=None),
    token: Optional[str] = Query(default=None),
):
    """SSE stream of agent observations for a task."""
    _check_agent_enabled()

    # Allow either Authorization header or token query for EventSource compatibility
    if token and not authorization:
        authorization = f"Bearer {token}"

    _require_roles, _get_user_info = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])

    from core.agent.state import get_agent_task

    task = get_agent_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="agent task not found")

    if "admin" not in user_info.get("roles", []):
        if task.get("user") != user_info.get("user"):
            raise HTTPException(status_code=403, detail="Access denied")

    def event_stream():
        last_obs_count = 0
        heartbeat_counter = 0
        while True:
            try:
                t = get_agent_task(task_id)
                if not t:
                    yield f"event: end\ndata: {json.dumps({'error': 'task not found'})}\n\n"
                    break

                observations = t.get("observations", [])
                if len(observations) > last_obs_count:
                    for obs in observations[last_obs_count:]:
                        yield f"data: {json.dumps(obs)}\n\n"
                    last_obs_count = len(observations)
                    heartbeat_counter = 0

                if t.get("status") in ("completed", "failed", "cancelled"):
                    yield f"event: end\ndata: {json.dumps({'status': t['status'], 'result': t.get('result')})}\n\n"
                    break

                heartbeat_counter += 1
                if heartbeat_counter >= 30:
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
                time.sleep(1.0)
            except Exception as e:
                # Sanitize: don't leak internal paths or stack details to client
                safe_msg = type(e).__name__
                yield f"event: end\ndata: {json.dumps({'error': safe_msg})}\n\n"
                break

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/tasks/{task_id}/transcript")
def get_transcript(
    task_id: str,
    authorization: Optional[str] = Header(default=None),
):
    """Get the full conversation transcript for an agent task."""
    _check_agent_enabled()
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["admin"])

    from core.agent.state import get_agent_task

    task = get_agent_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="agent task not found")

    # Transcript is stored in observations for now
    return {"task_id": task_id, "observations": task.get("observations", [])}


@router.get("/config")
def get_config(
    authorization: Optional[str] = Header(default=None),
):
    """Get current agent configuration (admin only).

    Unlike execution endpoints, this does NOT require the agent system to be
    enabled - admins need to read config in order to enable the agent system.
    """
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["admin"])

    config = _get_agent_config()
    return AgentConfigResponse(
        enabled=config.enabled,
        provider=getattr(config, "provider", "anthropic"),
        model=config.model,
        budget=config.budget.model_dump(),
        agents={k: v.model_dump() for k, v in config.agents.items()},
    )


@router.post("/config")
def update_config(
    body: UpdateAgentConfigRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Update agent configuration at runtime (admin only).

    Changes are applied to environment variables and take effect on
    the next agent task. The on-disk config file is not modified.
    """
    _require_roles, _ = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin"])

    changes: Dict[str, Any] = {}
    if body.enabled is not None:
        os.environ["AODS_AGENT_ENABLED"] = "1" if body.enabled else "0"
        changes["enabled"] = body.enabled
    if body.provider is not None:
        os.environ["AODS_AGENT_PROVIDER"] = body.provider
        changes["provider"] = body.provider
    if body.model is not None:
        os.environ["AODS_AGENT_MODEL"] = body.model
        changes["model"] = body.model
    if body.max_iterations is not None:
        os.environ["AODS_AGENT_MAX_ITERATIONS"] = str(body.max_iterations)
        changes["max_iterations"] = body.max_iterations
    if body.max_wall_time_seconds is not None:
        os.environ["AODS_AGENT_MAX_WALL_TIME"] = str(body.max_wall_time_seconds)
        changes["max_wall_time_seconds"] = body.max_wall_time_seconds
    if body.cost_limit_usd is not None:
        os.environ["AODS_AGENT_COST_LIMIT"] = str(body.cost_limit_usd)
        changes["cost_limit_usd"] = body.cost_limit_usd

    logger.info(
        "agent_config_updated",
        user=user_info.get("user", "unknown"),
        changes=changes,
    )

    # Re-read config (picks up env changes) and return updated state
    config = _get_agent_config()
    return AgentConfigResponse(
        enabled=config.enabled,
        provider=getattr(config, "provider", "anthropic"),
        model=config.model,
        budget=config.budget.model_dump(),
        agents={k: v.model_dump() for k, v in config.agents.items()},
    )


class AgentStatsResponse(BaseModel):
    """Response for aggregated agent statistics."""

    model_config = ConfigDict(extra="forbid")

    total_tasks: int = 0
    total_tokens: int = 0
    avg_elapsed_seconds: float = 0.0
    by_agent_type: Dict[str, Any] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    recent_trend: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/stats")
def get_agent_stats(
    days: int = Query(7, ge=1, le=90, description="Number of days to aggregate"),
    authorization: Optional[str] = Header(default=None),
):
    """Get aggregated agent performance statistics.

    Computes task counts, token totals, per-agent breakdowns, and daily
    trends from the in-memory task store.  Data does not persist across
    server restarts.
    """
    _check_agent_enabled()
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["admin", "analyst"])

    from core.agent.state import list_agent_tasks
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    all_tasks = list_agent_tasks(limit=500)

    # Filter by date
    tasks = []
    for t in all_tasks:
        try:
            created = t.get("created_at", "")
            if created:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if dt >= cutoff:
                    tasks.append(t)
        except (ValueError, TypeError):
            tasks.append(t)  # Include if we can't parse date

    total_tokens = 0
    total_elapsed = 0.0
    by_type: Dict[str, Dict[str, Any]] = {}
    by_status: Dict[str, int] = {}
    daily: Dict[str, Dict[str, Any]] = {}

    for t in tasks:
        usage = t.get("token_usage", {})
        inp = usage.get("input_tokens", 0)
        out = usage.get("output_tokens", 0)
        tokens = inp + out
        total_tokens += tokens

        # Estimate elapsed from created_at to completed_at
        elapsed = 0.0
        try:
            ca = t.get("created_at", "")
            ea = t.get("completed_at")
            if ca and ea:
                dt_start = datetime.fromisoformat(ca.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(ea.replace("Z", "+00:00"))
                elapsed = max(0, (dt_end - dt_start).total_seconds())
        except (ValueError, TypeError):
            pass
        total_elapsed += elapsed

        # By agent type
        atype = t.get("agent_type", "unknown")
        if atype not in by_type:
            by_type[atype] = {"count": 0, "tokens": 0, "total_elapsed": 0.0}
        by_type[atype]["count"] += 1
        by_type[atype]["tokens"] += tokens
        by_type[atype]["total_elapsed"] += elapsed

        # By status
        status = t.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1

        # Daily trend
        try:
            date_str = t.get("created_at", "")[:10]
            if date_str:
                if date_str not in daily:
                    daily[date_str] = {"date": date_str, "tokens": 0, "count": 0}
                daily[date_str]["tokens"] += tokens
                daily[date_str]["count"] += 1
        except (IndexError, TypeError):
            pass

    n = len(tasks) or 1
    by_type_out = {}
    for k, v in by_type.items():
        cnt = v["count"] or 1
        by_type_out[k] = {
            "count": v["count"],
            "tokens": v["tokens"],
            "avg_elapsed": round(v["total_elapsed"] / cnt, 1),
        }

    recent_trend = sorted(daily.values(), key=lambda d: d["date"])

    return AgentStatsResponse(
        total_tasks=len(tasks),
        total_tokens=total_tokens,
        avg_elapsed_seconds=round(total_elapsed / n, 1),
        by_agent_type=by_type_out,
        by_status=by_status,
        recent_trend=recent_trend,
    )


@router.get("/triage/feedback/history")
def get_triage_feedback_history(
    finding_title: str = Query(..., description="Finding title to search history for"),
    n_results: int = Query(10, ge=1, le=50, description="Max results"),
    authorization: Optional[str] = Header(default=None),
):
    """Query historical triage feedback similar to a given finding.

    Uses vector DB semantic search to find past analyst decisions on
    similar findings, enabling consistency across triage sessions.
    """
    _check_agent_enabled()
    _require_roles, _ = _get_auth_helpers()
    _require_roles(authorization, ["admin", "analyst"])

    if os.environ.get("AODS_VECTOR_DB_ENABLED", "0").lower() not in ("1", "true"):
        return TriageFeedbackHistoryResponse(vector_db_available=False)

    try:
        from core.vector_db import get_semantic_finding_index

        idx = get_semantic_finding_index()
        if idx is None or not idx.is_available():
            return TriageFeedbackHistoryResponse(vector_db_available=False)

        results = idx.find_similar_by_text(finding_title, n_results=n_results)

        items: List[TriageFeedbackHistoryItem] = []
        for r in results:
            meta = r.get("metadata", {})
            # Include results that have triage feedback or triage classification
            is_feedback = meta.get("type") == "triage_feedback"
            has_triage = bool(meta.get("triage_classification"))
            if not is_feedback and not has_triage:
                continue

            items.append(TriageFeedbackHistoryItem(
                finding_title=meta.get("finding_title", meta.get("title", "")),
                action=meta.get("action", ""),
                new_classification=meta.get("new_classification", meta.get("triage_classification", "")),
                reason=meta.get("reason", meta.get("triage_reasoning", "")),
                user=meta.get("user", meta.get("owner_user_id", "")),
                timestamp=meta.get("timestamp", ""),
                scan_id=meta.get("scan_id", ""),
                similarity_score=round(r.get("similarity", 0.0), 4),
            ))

        return TriageFeedbackHistoryResponse(
            results=items,
            total=len(items),
            vector_db_available=True,
        )
    except Exception as exc:
        logger.debug("triage_feedback_history_error", error=str(exc))
        return TriageFeedbackHistoryResponse(vector_db_available=True)


@router.get("/triage/feedback/export")
def export_triage_feedback(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID (optional)"),
    format: str = Query("json", description="Export format", pattern="^json$"),
    authorization: Optional[str] = Header(default=None),
):
    """Export triage feedback entries from scan reports.

    If scan_id is provided, returns feedback from that specific report.
    Otherwise, scans the most recent reports (up to 20) for feedback.
    """
    _require_roles, _ = _get_auth_helpers()
    user_info = _require_roles(authorization, ["admin", "analyst"])
    username = user_info.get("user", "unknown")

    from core.api.auth_helpers import _audit

    reports_dir = _REPO_ROOT / "reports"
    all_feedback: List[Dict[str, Any]] = []
    scan_ids: List[str] = []

    if scan_id:
        # Find report matching the given scan_id
        if not reports_dir.is_dir():
            _audit("triage_feedback_export", username, details={"scan_id": scan_id, "count": 0})
            return {"feedback": [], "count": 0, "scan_ids": []}

        found = False
        for rp in sorted(reports_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(rp, "r") as f:
                    data = json.load(f)
                sid = data.get("session_id") or data.get("scan_id", "")
                if sid == scan_id:
                    found = True
                    fb_list = data.get("triage_feedback", [])
                    for fb in fb_list:
                        fb["scan_id"] = sid
                    all_feedback.extend(fb_list)
                    if fb_list:
                        scan_ids.append(sid)
                    break
            except (json.JSONDecodeError, OSError):
                continue

        if not found:
            raise HTTPException(status_code=404, detail="report not found")
    else:
        # Scan most recent reports (up to 20) for feedback
        if reports_dir.is_dir():
            report_files = sorted(
                reports_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )[:20]
            for rp in report_files:
                try:
                    with open(rp, "r") as f:
                        data = json.load(f)
                    fb_list = data.get("triage_feedback", [])
                    if fb_list:
                        sid = data.get("session_id") or data.get("scan_id", "")
                        for fb in fb_list:
                            fb["scan_id"] = sid
                        all_feedback.extend(fb_list)
                        scan_ids.append(sid)
                except (json.JSONDecodeError, OSError):
                    continue

    _audit("triage_feedback_export", username, details={
        "scan_id": scan_id,
        "count": len(all_feedback),
        "scan_ids_count": len(scan_ids),
    })

    return {"feedback": all_feedback, "count": len(all_feedback), "scan_ids": scan_ids}
