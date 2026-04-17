from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

_manager = None


def get_objection_manager():
    global _manager
    if _manager is None:
        from core.objection_manager import ObjectionManager
        _manager = ObjectionManager()
    return _manager


class StartRequest(BaseModel):
    gadget: str           # bundle ID (iOS) or package name (Android)
    device_serial: str | None = None   # Frida device ID / ADB serial


class CommandRequest(BaseModel):
    command: str


@router.post("/sessions", status_code=201)
async def start_session(body: StartRequest):
    """Spawn an objection explore session."""
    import shutil, traceback
    mgr = get_objection_manager()

    # Pre-flight: surface a clear error if objection isn't on PATH
    if not shutil.which("objection"):
        raise HTTPException(500, (
            "objection not found on PATH. "
            "Install it in your active venv: "
            "pip install objection==1.12.0 --no-deps && "
            "pip install click prompt_toolkit watchdog requests packaging"
        ))

    try:
        session_id = await mgr.start(body.gadget, body.device_serial)
    except Exception as e:
        raise HTTPException(500, f"{type(e).__name__}: {e}\n{traceback.format_exc()}")
    return {"session_id": session_id, "gadget": body.gadget}


@router.delete("/sessions/{session_id}")
async def stop_session(session_id: str):
    """Terminate an objection session."""
    mgr = get_objection_manager()
    await mgr.stop(session_id)
    return {"status": "stopped"}


@router.post("/sessions/{session_id}/command")
async def send_command(session_id: str, body: CommandRequest):
    """Send a command to a running objection REPL."""
    mgr = get_objection_manager()
    try:
        await mgr.send_command(session_id, body.command)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return {"status": "sent"}


@router.get("/sessions")
async def list_sessions():
    """List all active objection sessions."""
    mgr = get_objection_manager()
    return mgr.list_sessions()
