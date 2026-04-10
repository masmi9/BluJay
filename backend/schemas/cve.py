from datetime import datetime

from pydantic import BaseModel


class DetectedLibraryOut(BaseModel):
    id: int
    analysis_id: int
    name: str
    version: str | None
    ecosystem: str
    source: str

    model_config = {"from_attributes": True}


class CveMatchOut(BaseModel):
    id: int
    analysis_id: int
    library_id: int
    osv_id: str
    cve_id: str | None
    severity: str | None
    cvss_score: float | None
    summary: str | None
    fixed_version: str | None
    published: str | None
    fetched_at: datetime

    model_config = {"from_attributes": True}


class CveScanResponse(BaseModel):
    libraries: list[DetectedLibraryOut]
    cve_matches: list[CveMatchOut]
    total_critical: int
    total_high: int
