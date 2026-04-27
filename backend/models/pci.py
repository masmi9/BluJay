from datetime import datetime

from sqlalchemy import Float, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class PciScanJob(Base):
    __tablename__ = "pci_scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_urls: Mapped[str] = mapped_column(Text)                # JSON list (quick scan)
    scope_config: Mapped[str | None] = mapped_column(Text, nullable=True)   # full YAML/JSON scope
    categories: Mapped[str] = mapped_column(Text, default="[]")
    scan_profile: Mapped[str] = mapped_column(default="web_only")  # web_only | external_pci | full_cde
    status: Mapped[str] = mapped_column(default="pending")          # pending|running|done|error
    phase: Mapped[str | None] = mapped_column(nullable=True)        # current phase
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    hosts_found: Mapped[int] = mapped_column(default=0)
    ports_open: Mapped[int] = mapped_column(default=0)
    pages_crawled: Mapped[int] = mapped_column(default=0)
    processors_detected: Mapped[str] = mapped_column(Text, default="[]")    # JSON list
    report_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_html_exec: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_html_tech: Mapped[str | None] = mapped_column(Text, nullable=True)
    flow_steps_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of PaymentFlowResult
    flow_steps_count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())


class PciFinding(Base):
    __tablename__ = "pci_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(index=True)
    url: Mapped[str] = mapped_column(Text)            # original URL (may be empty for network findings)
    host: Mapped[str]
    check_name: Mapped[str]
    severity: Mapped[str]
    category: Mapped[str]
    phase: Mapped[str | None] = mapped_column(nullable=True)      # scan phase that found this
    title: Mapped[str]
    detail: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)       # plain text summary
    evidence_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # full JSON evidence
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    pci_req: Mapped[str | None] = mapped_column(nullable=True)
    port: Mapped[int | None] = mapped_column(nullable=True)
    service: Mapped[str | None] = mapped_column(nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_ids: Mapped[str | None] = mapped_column(Text, nullable=True)    # JSON list
    plugin_id: Mapped[str | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
