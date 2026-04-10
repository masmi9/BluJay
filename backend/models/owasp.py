from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class OwaspScan(Base):
    __tablename__ = "owasp_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    platform: Mapped[str] = mapped_column(default="android")  # android | ios
    apk_path: Mapped[str]
    package_name: Mapped[str | None]
    mode: Mapped[str] = mapped_column(default="deep")   # deep | quick
    status: Mapped[str] = mapped_column(default="pending")
    # pending | running | complete | failed
    progress: Mapped[int] = mapped_column(default=0)    # 0-100
    findings_json: Mapped[str | None] = mapped_column(Text)  # full JSON from AODS
    summary_json: Mapped[str | None] = mapped_column(Text)   # executive summary
    report_html: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    duration_s: Mapped[float | None]
