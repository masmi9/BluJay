"""
Agent Console API — communicates with MobileMorphAgent on the device
via ADB port-forward + JSON socket protocol (port 31415).
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pathlib import Path

from config import settings
from core import adb_manager, build_manager
from core.morphagent_client import AGENT_PORT, SUPPORTED_COMMANDS, ping_agent, run_command
from database import get_db
from models.agent import AgentCommand

MORPH_PACKAGE = "com.mobilemorph.agent"
MORPH_SERVICE = ".services.ServerSocketService"

router = APIRouter()


class RunCommandRequest(BaseModel):
    serial: str
    command: str
    args: dict = {}
    timeout: float = 60.0


class SetupRequest(BaseModel):
    serial: str
    apk_path: str | None = None          # override config default
    start_service: bool = True


@router.post("/setup", summary="Install MobileMorphAgent APK + set up ADB port forward")
async def setup_agent(body: SetupRequest):
    """
    1. Install (or force-reinstall) the APK.
    2. Run adb forward tcp:31415 tcp:31415.
    3. Start the agent service — tries direct am start-foreground-service first,
       falls back to launching MainActivity so the service starts from a foreground context.
    4. Retries ping up to 5 times with 1 s gaps.
    """
    import asyncio
    steps: dict[str, str | bool] = {}

    # Resolve APK path: explicit override → config default → last successful build output
    build_state = build_manager.get_state()
    apk_path = (
        body.apk_path
        or (settings.morph_agent_apk if settings.morph_agent_apk and Path(settings.morph_agent_apk).exists() else None)
        or (build_state.apk_path if build_state.apk_path and Path(build_state.apk_path).exists() else None)
    )
    already_installed = await adb_manager.is_package_installed(body.serial, MORPH_PACKAGE)

    # Always reinstall when an APK path is explicitly provided (picks up manifest changes)
    if apk_path and Path(apk_path).exists():
        result = await adb_manager.install_apk(body.serial, Path(apk_path))
        steps["installed"] = result.success
        if not result.success:
            steps["install_error"] = result.message
            if not already_installed:
                return {"ok": False, "steps": steps}
            steps["install_note"] = "reinstall failed but package already present — continuing"
    elif not already_installed:
        raise HTTPException(400, "APK not found — build the APK first or set morph_agent_apk in config")
    else:
        steps["installed"] = True
        steps["install_skipped"] = "already installed, no APK path provided"

    forwarded = await adb_manager.forward_port(body.serial, AGENT_PORT, AGENT_PORT)
    steps["forwarded"] = forwarded

    if body.start_service:
        # Attempt 1: direct foreground service start (often blocked on Android 12+)
        started = await adb_manager.start_service(body.serial, MORPH_PACKAGE, MORPH_SERVICE)
        steps["service_started"] = started
        await asyncio.sleep(2.0)

        if not await ping_agent(body.serial):
            # Attempt 2: launch MainActivity — it calls startAgentService() on create,
            # which is the most reliable path on Android 12/13/14 physical devices
            steps["fallback_launch"] = "launching MainActivity"
            await adb_manager.launch_app(body.serial, MORPH_PACKAGE)
            # Give the app time to fully start and bind its ServerSocket
            await asyncio.sleep(4.0)

    # Retry ping up to 10 times with 1.5 s gaps (15 s total)
    reachable = False
    for attempt in range(10):
        if await ping_agent(body.serial):
            reachable = True
            break
        await asyncio.sleep(1.5)

    steps["reachable"] = reachable
    steps["ping_attempts"] = 5

    return {"ok": reachable, "steps": steps}


@router.post("/start-service", summary="Start (or restart) ServerSocketService on device")
async def start_service(serial: str):
    """
    Lightweight endpoint — just starts the service without reinstalling.
    Tries direct am start-foreground-service, falls back to launching MainActivity.
    """
    import asyncio

    forwarded = await adb_manager.forward_port(serial, AGENT_PORT, AGENT_PORT)

    started = await adb_manager.start_service(serial, MORPH_PACKAGE, MORPH_SERVICE)
    await asyncio.sleep(2.0)

    if not await ping_agent(serial):
        await adb_manager.launch_app(serial, MORPH_PACKAGE)
        await asyncio.sleep(4.0)

    reachable = False
    for _ in range(10):
        if await ping_agent(serial):
            reachable = True
            break
        await asyncio.sleep(1.5)

    return {"forwarded": forwarded, "started": started, "reachable": reachable}


@router.get("/status/{serial}", summary="Check MobileMorphAgent status on a device")
async def agent_status(serial: str):
    installed = await adb_manager.is_package_installed(serial, MORPH_PACKAGE)
    forwarded = await adb_manager.forward_port(serial, AGENT_PORT, AGENT_PORT) if installed else False
    reachable = await ping_agent(serial) if forwarded else False
    return {
        "serial": serial,
        "installed": installed,
        "forwarded": forwarded,
        "reachable": reachable,
        "morph_apk_configured": bool(settings.morph_agent_apk),
    }


@router.post("/build-apk", summary="Build MobileMorphAgent APK via Gradle")
async def build_apk():
    """
    Triggers `gradlew assembleDebug` in the MobileMorphAgent project directory.
    Returns immediately — poll /agent/build-status for progress.
    """
    project = settings.morph_agent_project
    apk_out = settings.morph_agent_apk

    if not project:
        raise HTTPException(400, "morph_agent_project not configured in settings")
    if not Path(project).exists():
        raise HTTPException(400, f"Project directory not found: {project}")

    started = build_manager.start_build(project, apk_out)
    if not started:
        raise HTTPException(409, "A build is already in progress")
    return {"status": "building", "message": "Gradle build started"}


@router.get("/build-status", summary="Get current MobileMorphAgent build status + log")
async def build_status(last_line: int = 0):
    """
    Returns build state + new log lines since `last_line` (use for polling).
    `last_line` = index of the last line the client already has.
    """
    state = build_manager.get_state()
    new_lines = state.log_lines[last_line:]
    return {
        "status": state.status,
        "total_lines": len(state.log_lines),
        "new_lines": new_lines,
        "apk_path": state.apk_path,
        "error": state.error,
    }


@router.get("/commands", summary="Supported MorphAgent command types")
async def list_commands():
    return {"commands": SUPPORTED_COMMANDS}


@router.post("/run", summary="Execute a command on the connected MobileMorphAgent")
async def run_agent_command(
    body: RunCommandRequest,
    db: AsyncSession = Depends(get_db),
):
    if body.command not in SUPPORTED_COMMANDS:
        raise HTTPException(400, f"Unknown command '{body.command}'. Supported: {SUPPORTED_COMMANDS}")

    # Persist as pending
    record = AgentCommand(
        device_serial=body.serial,
        command_type=body.command,
        args=json.dumps(body.args),
        status="running",
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    # Execute
    result = await run_command(body.serial, body.command, body.args, timeout=body.timeout)

    # Update record
    record.status = "complete" if result.get("status") == "success" else "error"
    record.result = json.dumps(result.get("data") or result.get("result"))
    record.error = result.get("error")
    record.duration_ms = result.get("duration_ms")
    await db.commit()

    return {
        "id": record.id,
        "status": record.status,
        "command": body.command,
        "result": result.get("data") or result.get("result"),
        "error": result.get("error"),
        "duration_ms": result.get("duration_ms"),
    }


@router.get("/history", summary="Command history for a device")
async def command_history(
    serial: str = Query(...),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(AgentCommand)
        .where(AgentCommand.device_serial == serial)
        .order_by(AgentCommand.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "command_type": r.command_type,
            "args": json.loads(r.args or "{}"),
            "result": json.loads(r.result) if r.result else None,
            "status": r.status,
            "error": r.error,
            "duration_ms": r.duration_ms,
        }
        for r in rows
    ]


@router.delete("/history", summary="Clear command history for a device")
async def clear_history(serial: str = Query(...), db: AsyncSession = Depends(get_db)):
    from sqlalchemy import delete
    await db.execute(delete(AgentCommand).where(AgentCommand.device_serial == serial))
    await db.commit()
    return {"status": "cleared"}
