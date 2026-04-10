from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.session import DynamicSession
from schemas.session import DynamicSessionCreate, DynamicSessionOut

router = APIRouter()


@router.post("", response_model=DynamicSessionOut, status_code=201)
async def create_session(body: DynamicSessionCreate, db: AsyncSession = Depends(get_db)):
    sess = DynamicSession(
        analysis_id=body.analysis_id,
        device_serial=body.device_serial,
        package_name=body.package_name,
    )
    db.add(sess)
    await db.commit()
    await db.refresh(sess)

    # Start logcat
    from core.logcat_streamer import logcat_streamer
    await logcat_streamer.start(sess.id, body.device_serial, body.package_name)

    return sess


@router.get("/{session_id}", response_model=DynamicSessionOut)
async def get_session(session_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DynamicSession).where(DynamicSession.id == session_id))
    sess = result.scalar_one_or_none()
    if not sess:
        raise HTTPException(404, "Session not found")
    return sess


@router.delete("/{session_id}", status_code=204)
async def stop_session(session_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DynamicSession).where(DynamicSession.id == session_id))
    sess = result.scalar_one_or_none()
    if not sess:
        raise HTTPException(404, "Session not found")

    # Stop logcat
    from core.logcat_streamer import logcat_streamer
    await logcat_streamer.stop(session_id)

    # Stop proxy if running
    from api.router import get_proxy_manager
    pm = get_proxy_manager()
    await pm.stop(session_id)

    # Detach Frida if attached
    from api.router import get_frida_manager
    fm = get_frida_manager()
    await fm.detach(session_id)

    sess.status = "stopped"
    await db.commit()
