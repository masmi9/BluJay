from datetime import datetime

from pydantic import BaseModel


class CampaignCreate(BaseModel):
    name: str
    description: str | None = None
    platform: str = "android"   # android | ios | mixed


class CampaignTargetOut(BaseModel):
    id: int
    apk_filename: str
    analysis_id: int | None
    status: str
    error: str | None

    model_config = {"from_attributes": True}


class CampaignOut(BaseModel):
    id: int
    created_at: datetime
    name: str
    description: str | None
    platform: str
    status: str
    targets: list[CampaignTargetOut] = []

    model_config = {"from_attributes": True}


class CampaignSummary(BaseModel):
    id: int
    created_at: datetime
    name: str
    platform: str
    status: str
    total: int = 0
    complete: int = 0
    failed: int = 0

    model_config = {"from_attributes": True}
