from datetime import datetime

from sqlalchemy import Float, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class DetectedLibrary(Base):
    __tablename__ = "detected_libraries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    version: Mapped[str | None]
    ecosystem: Mapped[str]  # Maven | npm | PyPI etc.
    source: Mapped[str]     # build.gradle | import_scan | strings_xml

    cve_matches: Mapped[list["CveMatch"]] = relationship(
        back_populates="library", cascade="all, delete-orphan"
    )


class CveMatch(Base):
    __tablename__ = "cve_matches"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    library_id: Mapped[int] = mapped_column(
        ForeignKey("detected_libraries.id", ondelete="CASCADE"), index=True
    )
    osv_id: Mapped[str]
    cve_id: Mapped[str | None]
    severity: Mapped[str | None]       # critical | high | medium | low
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixed_version: Mapped[str | None]
    published: Mapped[str | None]
    fetched_at: Mapped[datetime] = mapped_column(default=func.now())

    library: Mapped["DetectedLibrary"] = relationship(back_populates="cve_matches")
