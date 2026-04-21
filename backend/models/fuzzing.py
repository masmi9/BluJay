from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class FuzzJob(Base):
    __tablename__ = "fuzz_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error
    attacks: Mapped[str | None] = mapped_column(Text, nullable=True)       # JSON list of attack names
    endpoint_count: Mapped[int] = mapped_column(default=0)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["FuzzResult"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class FuzzResult(Base):
    __tablename__ = "fuzz_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("fuzz_jobs.id", ondelete="CASCADE"), index=True)
    attack_type: Mapped[str]
    method: Mapped[str]
    url: Mapped[str] = mapped_column(Text)
    response_status: Mapped[int | None]
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float | None]
    is_interesting: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    job: Mapped["FuzzJob"] = relationship(back_populates="results")
