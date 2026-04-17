from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AnalysisDiff(Base):
    __tablename__ = "analysis_diffs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())

    # baseline = "before" analysis; target = "after" analysis
    baseline_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )

    diff_type: Mapped[str] = mapped_column(default="full")  # permissions | findings | libraries | full

    added_findings: Mapped[str | None] = mapped_column(Text, nullable=True)      # JSON list
    removed_findings: Mapped[str | None] = mapped_column(Text, nullable=True)    # JSON list
    added_permissions: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON list
    removed_permissions: Mapped[str | None] = mapped_column(Text, nullable=True) # JSON list
    severity_delta: Mapped[str | None] = mapped_column(Text, nullable=True)      # JSON e.g. {"critical":2,"high":-1}
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
