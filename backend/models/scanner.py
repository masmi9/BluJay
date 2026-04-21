from datetime import datetime

from sqlalchemy import Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int | None] = mapped_column(nullable=True, index=True)
    flow_id: Mapped[str | None] = mapped_column(nullable=True)
    scan_job_id: Mapped[int | None] = mapped_column(nullable=True, index=True)
    scan_type: Mapped[str]                    # "passive" | "active"
    check_name: Mapped[str]                   # e.g. "missing-security-headers"
    severity: Mapped[str]                     # "info" | "low" | "medium" | "high" | "critical"
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str]
    title: Mapped[str]
    detail: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(default=func.now())


class ActiveScanJob(Base):
    __tablename__ = "active_scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int | None] = mapped_column(nullable=True)
    flow_ids: Mapped[str] = mapped_column(Text)   # JSON list
    checks: Mapped[str] = mapped_column(Text)     # JSON list
    status: Mapped[str] = mapped_column(default="pending")  # pending|running|done|error
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    requests_sent: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
