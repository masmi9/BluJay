from datetime import datetime
from typing import Literal

from pydantic import BaseModel


SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
ScanType = Literal["passive", "active"]

ACTIVE_CHECKS = ["xss-reflected", "sqli-error", "open-redirect", "path-traversal", "ssrf-basic"]
PASSIVE_CHECKS = [
    "missing-security-headers", "insecure-cookie", "reflected-input",
    "sensitive-data-exposure", "info-disclosure", "cors-misconfiguration",
]


class ScanFindingOut(BaseModel):
    id: int
    session_id: int | None
    flow_id: str | None
    scan_job_id: int | None
    scan_type: ScanType
    check_name: str
    severity: SeverityLevel
    url: str
    host: str
    title: str
    detail: str
    evidence: str | None
    remediation: str | None
    timestamp: datetime

    model_config = {"from_attributes": True}


class ActiveScanJobOut(BaseModel):
    id: int
    session_id: int | None
    flow_ids: list[str]
    checks: list[str]
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int
    requests_sent: int
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class StartActiveScanRequest(BaseModel):
    session_id: int | None = None
    flow_ids: list[str] = []
    target_urls: list[str] = []   # direct URL targets — no prior proxy capture needed
    checks: list[str] = ACTIVE_CHECKS


class ScanUrlRequest(BaseModel):
    url: str
    session_id: int | None = None


class ScanUrlResult(BaseModel):
    url: str
    findings: list[ScanFindingOut]


class FindingsResponse(BaseModel):
    total: int
    items: list[ScanFindingOut]
