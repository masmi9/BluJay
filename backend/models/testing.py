from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class TestApp(Base):
    """Registry of real apps used as test targets."""
    __tablename__ = "test_apps"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    display_name: Mapped[str]
    package_name: Mapped[str] = mapped_column(index=True)
    apk_path: Mapped[str | None]
    category: Mapped[str | None]      # e.g. "banking", "social", "goat"
    description: Mapped[str | None] = mapped_column(Text)
    is_vulnerable_app: Mapped[bool] = mapped_column(default=False)  # deliberately vulnerable (DIVA, goat, etc.)

    runs: Mapped[list["TestRun"]] = relationship(back_populates="test_app", cascade="all, delete-orphan")


class TestRun(Base):
    """A single test execution against a TestApp — tracks script, results, accuracy."""
    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    test_app_id: Mapped[int] = mapped_column(ForeignKey("test_apps.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True
    )
    owasp_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("owasp_scans.id", ondelete="SET NULL"), nullable=True
    )

    # Frida script used
    frida_script_name: Mapped[str | None]
    frida_script_source: Mapped[str | None] = mapped_column(Text)

    # Structured findings from this run (JSON list)
    findings_json: Mapped[str | None] = mapped_column(Text)

    # Reproduction block auto-generated from findings
    reproduction_steps: Mapped[str | None] = mapped_column(Text)  # JSON list of step dicts

    # Accuracy tracking
    true_positives: Mapped[int] = mapped_column(default=0)
    false_positives: Mapped[int] = mapped_column(default=0)
    false_negatives: Mapped[int] = mapped_column(default=0)

    notes: Mapped[str | None] = mapped_column(Text)

    test_app: Mapped["TestApp"] = relationship(back_populates="runs")
