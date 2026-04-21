from datetime import datetime

from pydantic import BaseModel


class FuzzJobCreate(BaseModel):
    session_id: int | None = None
    analysis_id: int | None = None
    attacks: list[str] = ["idor", "verb_tampering", "auth_bypass", "rate_limit"]
    endpoint_filter: str | None = None  # regex to filter URLs
    base_url: str = ""  # used for static endpoint extraction


class FuzzJobOut(BaseModel):
    id: int
    created_at: datetime
    session_id: int | None
    analysis_id: int | None
    status: str
    attacks: str | None
    endpoint_count: int
    result_summary: str | None
    error: str | None

    model_config = {"from_attributes": True}


class FuzzResultOut(BaseModel):
    id: int
    job_id: int
    attack_type: str
    method: str
    url: str
    response_status: int | None
    response_body: str | None
    duration_ms: float | None
    is_interesting: bool
    notes: str | None

    model_config = {"from_attributes": True}


class FuzzJobDetail(FuzzJobOut):
    results: list[FuzzResultOut] = []
