from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.session import FridaEvent
from schemas.frida import (
    FridaAttachRequest,
    FridaEventsResponse,
    FridaLoadScriptRequest,
    FridaScriptInfo,
    FridaScriptLoaded,
)

router = APIRouter()


@router.get("/processes/{serial}", summary="Enumerate running processes and installed apps on a device via Frida")
async def list_processes(serial: str):
    """Returns list of {pid, name, identifier, running} for all processes and installed apps visible to frida-server.
    Merges enumerate_processes() (running only) with enumerate_applications() (all installed) so apps like
    Lemon8 appear even when not currently running."""
    import asyncio, functools
    try:
        import frida
    except ImportError:
        raise HTTPException(500, "frida Python package not installed")

    def _enumerate():
        try:
            mgr = frida.get_device_manager()
            device = mgr.get_device(serial, timeout=5)

            # Build a map of running processes keyed by both name and pid for merging.
            running_procs: list[dict] = []
            running_by_name: dict[str, int] = {}
            try:
                for p in device.enumerate_processes():
                    running_by_name[p.name.lower()] = p.pid
                    running_procs.append({"pid": p.pid, "name": p.name, "identifier": None, "running": True})
            except Exception:
                pass

            # Try enumerate_applications to get all installed apps with bundle IDs.
            # scope="full" (Frida 15+) populates the pid field for running apps.
            # Fall back to no scope arg for older frida-server versions.
            apps: list[dict] = []
            try:
                for app in device.enumerate_applications(scope="full"):
                    identifier = getattr(app, "identifier", None) or ""
                    name = app.name or identifier
                    pid = getattr(app, "pid", 0) or 0
                    running = pid > 0
                    apps.append({
                        "pid": pid if running else None,
                        "name": name,
                        "identifier": identifier,
                        "running": running,
                    })
            except Exception:
                # scope="full" not supported by this frida-server version — retry without it
                try:
                    for app in device.enumerate_applications():
                        identifier = getattr(app, "identifier", None) or ""
                        name = app.name or identifier
                        # No pid in this mode — check running_by_name to fill it in
                        pid = running_by_name.get(name.lower(), 0)
                        running = pid > 0
                        apps.append({
                            "pid": pid if running else None,
                            "name": name,
                            "identifier": identifier,
                            "running": running,
                        })
                except Exception:
                    pass

            # If enumerate_applications returned nothing, fall back to processes only
            if not apps:
                return sorted(running_procs, key=lambda a: a["name"].lower())

            # Merge: add any running processes not already covered by an app entry.
            # This catches system daemons and apps whose process name differs from
            # their bundle ID (e.g. com.bd.nproject running as "lemon8").
            app_identifiers = {a["identifier"].lower() for a in apps if a["identifier"]}
            app_names = {a["name"].lower() for a in apps}
            for proc in running_procs:
                pname = proc["name"].lower()
                if pname not in app_identifiers and pname not in app_names:
                    apps.append(proc)

            return sorted(apps, key=lambda a: a["name"].lower())

        except frida.InvalidArgumentError:
            raise HTTPException(404, f"Device {serial} not found by frida — is frida-server running?")
        except Exception as e:
            raise HTTPException(500, str(e))

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _enumerate)


@router.get("/scripts", response_model=list[FridaScriptInfo])
async def list_scripts():
    from core.frida_manager import BUILTIN_SCRIPTS
    return [
        FridaScriptInfo(
            name=meta["name"],
            filename=meta["filename"],
            description=meta["description"],
            hooks=meta["hooks"],
        )
        for key, meta in BUILTIN_SCRIPTS.items()
    ]


@router.post("/sessions")
async def attach_frida(body: FridaAttachRequest):
    from api.router import get_frida_manager
    fm = get_frida_manager()
    try:
        result = await fm.attach(body.session_id, body.device_serial, body.package_name)
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    return result


@router.delete("/sessions/{session_id}")
async def detach_frida(session_id: int):
    from api.router import get_frida_manager
    fm = get_frida_manager()
    await fm.detach(session_id)
    return {"status": "detached"}


@router.post("/sessions/{session_id}/scripts", response_model=FridaScriptLoaded)
async def load_script(session_id: int, body: FridaLoadScriptRequest):
    from api.router import get_frida_manager
    fm = get_frida_manager()
    try:
        if body.builtin_name:
            script_id = await fm.load_builtin(session_id, body.builtin_name)
            from core.frida_manager import BUILTIN_SCRIPTS
            name = BUILTIN_SCRIPTS[body.builtin_name]["name"]
        elif body.source:
            script_id = await fm.load_script(session_id, "custom", body.source)
            name = "custom"
        else:
            raise HTTPException(400, "Either builtin_name or source must be provided")
    except (RuntimeError, ValueError, FileNotFoundError) as e:
        raise HTTPException(400, str(e))
    return FridaScriptLoaded(script_id=script_id, name=name)


@router.delete("/sessions/{session_id}/scripts/{script_id}")
async def unload_script(session_id: int, script_id: str):
    from api.router import get_frida_manager
    fm = get_frida_manager()
    await fm.unload_script(session_id, script_id)
    return {"status": "unloaded"}


@router.get("/events", response_model=FridaEventsResponse)
async def get_events(
    session_id: int = Query(...),
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    q = select(FridaEvent).where(FridaEvent.session_id == session_id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    items = (await db.execute(q.order_by(FridaEvent.timestamp.desc()).offset(skip).limit(limit))).scalars().all()
    return {"total": total, "items": items}
