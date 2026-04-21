from datetime import datetime

from pydantic import BaseModel


class BruteForceJobCreate(BaseModel):
    target_url: str
    auth_type: str = "form"       # form | json | basic
    username_field: str = "username"
    password_field: str = "password"
    username: str
    wordlist_path: str | None = None
    concurrency: int = 5
    rate_limit_rps: float = 10.0


class BruteForceJobOut(BaseModel):
    id: int
    created_at: datetime
    target_url: str
    auth_type: str
    username_field: str
    password_field: str
    username: str
    concurrency: int
    rate_limit_rps: float
    status: str
    attempts_made: int
    credentials_found: str | None
    error: str | None

    model_config = {"from_attributes": True}


class BruteForceAttemptOut(BaseModel):
    id: int
    job_id: int
    username: str
    password: str
    status_code: int | None
    success: bool
    timestamp: datetime

    model_config = {"from_attributes": True}


class BruteForceCredential(BaseModel):
    username: str
    password: str


class DetectEndpointsRequest(BaseModel):
    session_id: int
