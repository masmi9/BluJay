from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class AIAgentScan(Base):
    __tablename__ = "ai_agent_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error | cancelled
    target_url: Mapped[str]
    protocol_type: Mapped[str]  # openai_compat | mcp | a2a | rest
    probe_categories: Mapped[str] = mapped_column(Text)  # JSON list e.g. ["infra","prompt_injection"]
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())

    findings: Mapped[list["AIAgentFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class AIAgentFinding(Base):
    __tablename__ = "ai_agent_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("ai_agent_scans.id", ondelete="CASCADE"), index=True)
    category: Mapped[str]   # infra | prompt_injection | tool_abuse | data_exfil
    severity: Mapped[str]   # critical | high | medium | low | info
    title: Mapped[str]
    detail: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    probe_id: Mapped[str]   # e.g. "infra-agent-json-exposed"
    request_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    confirmed: Mapped[bool] = mapped_column(default=False)
    timestamp: Mapped[datetime] = mapped_column(default=func.now())

    scan: Mapped["AIAgentScan"] = relationship(back_populates="findings")
