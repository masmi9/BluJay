from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from config import settings
from core import ios_device_manager
from schemas.ios_device import IosDeviceInfo

router = APIRouter()


class PullAnalyzeRequest(BaseModel):
    udid: str
    bundle_id: str


@router.get("", response_model=list[IosDeviceInfo])
async def list_ios_devices():
    return await ios_device_manager.get_devices()


@router.get("/{udid}/apps")
async def list_ios_apps(udid: str):
    return await ios_device_manager.list_apps(udid)


class PullIpaRequest(BaseModel):
    udid: str
    bundle_id: str


@router.post("/pull-ipa")
async def pull_ipa(body: PullIpaRequest):
    """Pull an IPA from the device and return its local path (does not run analysis)."""
    pulled_dir = settings.uploads_dir / "pulled_ios"
    try:
        ipa_path = await ios_device_manager.pull_ipa(body.udid, body.bundle_id, pulled_dir)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return {"ipa_path": str(ipa_path)}


@router.post("/pull-and-analyze", status_code=201)
async def pull_and_analyze(body: PullAnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Pull an IPA from the connected iOS device and run static analysis on it.
    Requires ideviceinstaller and either a jailbroken device or a sideloaded app.
    """
    import asyncio
    import hashlib
    from database import AsyncSessionLocal, get_db
    from models.analysis import Analysis
    from sqlalchemy import select

    pulled_dir = settings.uploads_dir / "pulled_ios"
    try:
        ipa_path = await ios_device_manager.pull_ipa(body.udid, body.bundle_id, pulled_dir)
    except RuntimeError as e:
        raise HTTPException(400, str(e))

    content = ipa_path.read_bytes()
    sha256 = hashlib.sha256(content).hexdigest()

    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(Analysis).where(Analysis.apk_sha256 == sha256))).scalar_one_or_none()
        if existing:
            return existing

        analysis = Analysis(
            apk_filename=ipa_path.name,
            apk_sha256=sha256,
            upload_path=str(ipa_path),
            platform="ios",
            status="pending",
        )
        db.add(analysis)
        await db.commit()
        await db.refresh(analysis)

        queue: asyncio.Queue = asyncio.Queue()

        async def _run():
            from core.ipa_analyzer import run_ipa_analysis
            await run_ipa_analysis(analysis.id, str(ipa_path), queue, AsyncSessionLocal)

        background_tasks.add_task(_run)
        return {"id": analysis.id, "status": "pending", "platform": "ios"}
