from datetime import datetime
from typing import Literal

from pydantic import BaseModel

PciSeverity = Literal["info", "low", "medium", "high", "critical"]


class PciFindingOut(BaseModel):
    id: int
    job_id: int
    url: str
    host: str
    check_name: str
    severity: PciSeverity
    category: str
    phase: str | None
    title: str
    detail: str
    evidence: str | None
    evidence_json: str | None
    remediation: str | None
    pci_req: str | None
    port: int | None
    service: str | None
    cvss_score: float | None
    cve_ids: str | None    # JSON list string
    plugin_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PciScanJobOut(BaseModel):
    id: int
    target_urls: list[str]
    scope_config: str | None
    categories: list[str]
    scan_profile: str
    status: str
    phase: str | None
    started_at: datetime | None
    finished_at: datetime | None
    finding_count: int
    hosts_found: int
    ports_open: int
    pages_crawled: int
    processors_detected: list[str]
    flow_steps_count: int = 0
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PciScanRequest(BaseModel):
    """Quick web-only scan: provide a list of target URLs."""
    target_urls: list[str]
    categories: list[str] = []
    scan_profile: str = "web_only"


class PciFullScanRequest(BaseModel):
    """Full PCI scan: provide YAML or JSON scope config."""
    scope_config: str                     # YAML or JSON string
    scan_profile: str = "external_pci"   # external_pci | full_cde | web_only
