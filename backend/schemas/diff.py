from datetime import datetime

from pydantic import BaseModel


class DiffRequest(BaseModel):
    baseline_id: int
    target_id: int
    diff_type: str = "full"   # full | findings | permissions | libraries


class FindingSnap(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    file_path: str | None = None
    rule_id: str | None = None


class DiffOut(BaseModel):
    id: int
    created_at: datetime
    baseline_id: int | None
    target_id: int | None
    diff_type: str
    added_findings: list[FindingSnap]
    removed_findings: list[FindingSnap]
    added_permissions: list[str]
    removed_permissions: list[str]
    severity_delta: dict[str, int]   # e.g. {"critical": 2, "high": -1}
    summary: str | None

    model_config = {"from_attributes": True}


class DiffSummary(BaseModel):
    id: int
    created_at: datetime
    baseline_id: int | None
    target_id: int | None
    diff_type: str
    summary: str | None

    model_config = {"from_attributes": True}
