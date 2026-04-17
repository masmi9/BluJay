"""
Multi-APK Campaign API.

POST /campaigns                        — create a campaign
GET  /campaigns                        — list all campaigns
GET  /campaigns/{id}                   — get campaign with targets
POST /campaigns/{id}/targets           — upload an APK/IPA and add as target
POST /campaigns/{id}/run               — start batch analysis
DELETE /campaigns/{id}                 — delete campaign
"""
import asyncio
import hashlib
from pathlib import Path

import aiofiles
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import AsyncSessionLocal, get_db
from models.analysis import Analysis
from models.campaign import CampaignJob, CampaignTarget
from schemas.campaign import CampaignCreate, CampaignOut, CampaignSummary

router = APIRouter()


# ── helpers ──────────────────────────────────────────────────────────────────

async def _run_target(target_id: int) -> None:
    """Background task: run analysis pipeline for one campaign target."""
    from api.analysis import _create_and_run
    from fastapi import BackgroundTasks as BT

    async with AsyncSessionLocal() as db:
        target = await db.scalar(select(CampaignTarget).where(CampaignTarget.id == target_id))
        if not target or not target.upload_path:
            return

        target.status = "running"
        await db.commit()

        try:
            bt = BT()
            analysis = await _create_and_run(
                Path(target.upload_path),
                target.apk_filename,
                bt,
                db,
            )
            # _create_and_run commits internally; re-fetch target after
            await db.refresh(target)
            target.analysis_id = analysis.id
            target.status = "complete"
            await db.commit()

            # Execute any background tasks queued by the pipeline
            for task in bt.tasks:
                await asyncio.get_event_loop().run_in_executor(None, task)

        except Exception as exc:
            await db.refresh(target)
            target.status = "failed"
            target.error = str(exc)
            await db.commit()


async def _run_campaign(campaign_id: int) -> None:
    """Background task: iterate pending targets and run each analysis."""
    async with AsyncSessionLocal() as db:
        campaign = await db.scalar(
            select(CampaignJob).where(CampaignJob.id == campaign_id)
        )
        if not campaign:
            return

        campaign.status = "running"
        await db.commit()

    # Run targets sequentially to avoid overwhelming the machine
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            select(CampaignTarget)
            .where(CampaignTarget.campaign_id == campaign_id)
            .where(CampaignTarget.status == "pending")
        )
        target_ids = [t.id for t in rows.scalars().all()]

    for tid in target_ids:
        await _run_target(tid)

    # Final campaign status
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            select(CampaignTarget).where(CampaignTarget.campaign_id == campaign_id)
        )
        targets = rows.scalars().all()
        statuses = {t.status for t in targets}
        campaign = await db.scalar(
            select(CampaignJob).where(CampaignJob.id == campaign_id)
        )
        if campaign:
            campaign.status = "complete" if "failed" not in statuses else "failed"
            await db.commit()


def _summary(c: CampaignJob) -> CampaignSummary:
    targets = c.targets
    return CampaignSummary(
        id=c.id,
        created_at=c.created_at,
        name=c.name,
        platform=c.platform,
        status=c.status,
        total=len(targets),
        complete=sum(1 for t in targets if t.status == "complete"),
        failed=sum(1 for t in targets if t.status == "failed"),
    )


# ── endpoints ────────────────────────────────────────────────────────────────

@router.post("", response_model=CampaignOut, status_code=201)
async def create_campaign(body: CampaignCreate, db: AsyncSession = Depends(get_db)):
    campaign = CampaignJob(
        name=body.name,
        description=body.description,
        platform=body.platform,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    return campaign


@router.get("", response_model=list[CampaignSummary])
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    from sqlalchemy.orm import selectinload
    rows = await db.execute(
        select(CampaignJob)
        .options(selectinload(CampaignJob.targets))
        .order_by(CampaignJob.created_at.desc())
    )
    return [_summary(c) for c in rows.scalars().all()]


@router.get("/{campaign_id}", response_model=CampaignOut)
async def get_campaign(campaign_id: int, db: AsyncSession = Depends(get_db)):
    from sqlalchemy.orm import selectinload
    campaign = await db.scalar(
        select(CampaignJob)
        .options(selectinload(CampaignJob.targets))
        .where(CampaignJob.id == campaign_id)
    )
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    return campaign


@router.post("/{campaign_id}/targets", response_model=CampaignOut, status_code=201)
async def add_target(
    campaign_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload an APK/IPA and add it as a pending target in the campaign."""
    from sqlalchemy.orm import selectinload

    campaign = await db.scalar(
        select(CampaignJob)
        .options(selectinload(CampaignJob.targets))
        .where(CampaignJob.id == campaign_id)
    )
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    if campaign.status == "running":
        raise HTTPException(409, "Campaign is already running — cannot add targets now")

    filename = file.filename or "upload.apk"
    upload_path = settings.uploads_dir / filename
    content = await file.read()

    async with aiofiles.open(upload_path, "wb") as f:
        await f.write(content)

    target = CampaignTarget(
        campaign_id=campaign_id,
        apk_filename=filename,
        upload_path=str(upload_path),
    )
    db.add(target)
    await db.commit()

    # Re-fetch with relationships
    campaign = await db.scalar(
        select(CampaignJob)
        .options(selectinload(CampaignJob.targets))
        .where(CampaignJob.id == campaign_id)
    )
    return campaign


@router.post("/{campaign_id}/run", response_model=CampaignOut)
async def run_campaign(
    campaign_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Start the analysis pipeline for all pending targets in this campaign."""
    from sqlalchemy.orm import selectinload

    campaign = await db.scalar(
        select(CampaignJob)
        .options(selectinload(CampaignJob.targets))
        .where(CampaignJob.id == campaign_id)
    )
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    if campaign.status == "running":
        raise HTTPException(409, "Campaign is already running")
    if not campaign.targets:
        raise HTTPException(400, "No targets in campaign — upload APKs first")

    background_tasks.add_task(_run_campaign, campaign_id)
    return campaign


@router.delete("/{campaign_id}", status_code=204)
async def delete_campaign(campaign_id: int, db: AsyncSession = Depends(get_db)):
    campaign = await db.scalar(
        select(CampaignJob).where(CampaignJob.id == campaign_id)
    )
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    await db.delete(campaign)
    await db.commit()
