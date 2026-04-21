"""
IODS FastAPI Server.

Endpoints (prefix /api):
  GET  /health                         → health check
  GET  /tools/status                   → external tool availability
  POST /scans/start                    → start a scan for an IPA
  GET  /scans/{session_id}/progress    → poll scan status
  GET  /scans/{session_id}/results     → get completed scan results
  GET  /scans/list                     → list all sessions
  POST /batch/submit                   → submit batch scan job
  GET  /batch/{job_id}/status          → batch job status
  POST /auth/token                     → create API token (dev/admin)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, APIRouter, Header, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from core.logging_config import configure_structlog, get_logger
from core.api.shared_state import (
    REPO_ROOT, _SESSIONS, _SESSIONS_LOCK, _BATCH_JOBS, _BATCH_LOCK
)
from core.api.auth_helpers import (
    _extract_token, create_token, _enforce_access
)

configure_structlog()
logger = get_logger(__name__)

app = FastAPI(
    title="IODS API",
    description="iOS OWASP Dynamic Scan Framework – REST API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

api = APIRouter(prefix="/api")


# ── Request / Response Models ─────────────────────────────────────────────────

class ScanOptions(BaseModel):
    profile: str = "standard"
    mode: str = "safe"
    formats: List[str] = ["json", "txt"]
    static_only: bool = True
    disable_ml: bool = False
    vulnerable_app_mode: bool = False
    device_udid: Optional[str] = None


class StartScanRequest(BaseModel):
    ipa_path: str
    options: ScanOptions = Field(default_factory=ScanOptions)


class BatchSubmitRequest(BaseModel):
    ipa_paths: List[str]
    options: ScanOptions = Field(default_factory=ScanOptions)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_scan_background(session_id: str, ipa_path: str, options: ScanOptions) -> None:
    """Run ios_scan.py in a subprocess and track status."""
    with _SESSIONS_LOCK:
        _SESSIONS[session_id]["status"] = "running"
        _SESSIONS[session_id]["start_time"] = time.time()

    cmd = [
        "python", str(REPO_ROOT / "ios_scan.py"),
        "--ipa", ipa_path,
        "--mode", options.mode,
        "--profile", options.profile,
        "--formats", *options.formats,
        "--output-dir", str(REPO_ROOT / "reports" / session_id),
    ]
    if options.static_only:
        cmd.append("--static-only")
    if options.disable_ml:
        cmd.append("--disable-ml")
    if options.vulnerable_app_mode:
        cmd.append("--vulnerable-app-mode")

    try:
        env = os.environ.copy()
        env["IODS_TEST_MODE"] = "0"
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)

        # Load results
        report_dir = REPO_ROOT / "reports" / session_id
        findings = []
        for json_file in report_dir.glob("*.json"):
            try:
                data = json.loads(json_file.read_text())
                findings = data.get("findings", [])
                break
            except Exception:
                pass

        with _SESSIONS_LOCK:
            _SESSIONS[session_id]["status"] = "completed" if result.returncode <= 1 else "failed"
            _SESSIONS[session_id]["exit_code"] = result.returncode
            _SESSIONS[session_id]["findings"] = findings
            _SESSIONS[session_id]["end_time"] = time.time()
            _SESSIONS[session_id]["report_dir"] = str(report_dir)
    except subprocess.TimeoutExpired:
        with _SESSIONS_LOCK:
            _SESSIONS[session_id]["status"] = "timeout"
    except Exception as e:
        with _SESSIONS_LOCK:
            _SESSIONS[session_id]["status"] = "failed"
            _SESSIONS[session_id]["error"] = str(e)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@api.get("/health")
def health():
    return {"status": "ok", "scanner": "IODS", "version": "1.0.0"}


@api.get("/tools/status")
def tools_status():
    tools = {
        "otool": _tool_available("otool"),
        "nm": _tool_available("nm"),
        "strings": _tool_available("strings"),
        "class-dump": _tool_available("class-dump"),
        "jtool2": _tool_available("jtool2"),
        "codesign": _tool_available("codesign"),
        "frida": _tool_available("frida"),
        "ideviceinfo": _tool_available("ideviceinfo"),
        "plutil": _tool_available("plutil"),
    }
    return {"tools": tools, "all_available": all(tools.values())}


@api.post("/scans/start")
def start_scan(request: StartScanRequest, authorization: Optional[str] = Header(None)):
    ipa_path = request.ipa_path
    if not Path(ipa_path).exists():
        raise HTTPException(status_code=400, detail=f"IPA file not found: {ipa_path}")

    session_id = str(uuid.uuid4())
    with _SESSIONS_LOCK:
        _SESSIONS[session_id] = {
            "session_id": session_id,
            "status": "queued",
            "ipa_path": ipa_path,
            "options": request.options.model_dump(),
            "findings": [],
            "created_at": time.time(),
        }

    thread = threading.Thread(
        target=_run_scan_background,
        args=(session_id, ipa_path, request.options),
        daemon=True,
    )
    thread.start()

    return {"session_id": session_id, "status": "queued", "message": "Scan started"}


@api.get("/scans/{session_id}/progress")
def get_scan_progress(session_id: str):
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session_id,
        "status": session.get("status"),
        "finding_count": len(session.get("findings", [])),
        "elapsed": time.time() - session.get("start_time", session.get("created_at", time.time())),
    }


@api.get("/scans/{session_id}/results")
def get_scan_results(session_id: str):
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") not in ("completed", "failed"):
        return {"session_id": session_id, "status": session.get("status"), "findings": []}
    return {
        "session_id": session_id,
        "status": session.get("status"),
        "findings": session.get("findings", []),
        "report_dir": session.get("report_dir"),
        "exit_code": session.get("exit_code"),
    }


@api.get("/scans/list")
def list_scans():
    with _SESSIONS_LOCK:
        sessions = [
            {"session_id": sid, "status": s.get("status"), "ipa_path": s.get("ipa_path")}
            for sid, s in _SESSIONS.items()
        ]
    return {"sessions": sessions, "total": len(sessions)}


@api.post("/batch/submit")
def submit_batch(request: BatchSubmitRequest):
    job_id = str(uuid.uuid4())
    with _BATCH_LOCK:
        _BATCH_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "ipa_paths": request.ipa_paths,
            "options": request.options.model_dump(),
            "sessions": [],
            "created_at": time.time(),
        }

    def _run_batch():
        sessions = []
        for ipa_path in request.ipa_paths:
            if not Path(ipa_path).exists():
                continue
            session_id = str(uuid.uuid4())
            with _SESSIONS_LOCK:
                _SESSIONS[session_id] = {
                    "session_id": session_id,
                    "status": "queued",
                    "ipa_path": ipa_path,
                    "findings": [],
                    "created_at": time.time(),
                }
            _run_scan_background(session_id, ipa_path, request.options)
            sessions.append(session_id)

        with _BATCH_LOCK:
            _BATCH_JOBS[job_id]["status"] = "completed"
            _BATCH_JOBS[job_id]["sessions"] = sessions

    thread = threading.Thread(target=_run_batch, daemon=True)
    thread.start()

    return {"job_id": job_id, "status": "queued"}


@api.get("/batch/{job_id}/status")
def batch_status(job_id: str):
    with _BATCH_LOCK:
        job = _BATCH_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Batch job not found")
    return job


@api.post("/auth/token")
def create_api_token(user_id: str = "dev", role: str = "analyst"):
    """Development endpoint to create API tokens. Secure in production."""
    token = create_token(user_id=user_id, role=role)
    return {"token": token, "user_id": user_id, "role": role}


@api.post("/scans/upload")
async def upload_and_scan(file: UploadFile = File(...), profile: str = "standard", mode: str = "safe"):
    """Upload an IPA file and start a scan."""
    upload_dir = Path("uploads")
    upload_dir.mkdir(exist_ok=True)

    ipa_path = upload_dir / f"{uuid.uuid4()}_{file.filename}"
    content = await file.read()
    ipa_path.write_bytes(content)

    options = ScanOptions(profile=profile, mode=mode)
    return start_scan(StartScanRequest(ipa_path=str(ipa_path), options=options))


# Register router
app.include_router(api)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8089)
