from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

if TYPE_CHECKING:
    from models.session import DynamicSession


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    apk_filename: Mapped[str]
    apk_sha256: Mapped[str] = mapped_column(unique=True, index=True)
    upload_path: Mapped[str | None]  # path to saved APK file

    # Parsed APK metadata
    package_name: Mapped[str | None]
    version_name: Mapped[str | None]
    version_code: Mapped[int | None]
    min_sdk: Mapped[int | None]
    target_sdk: Mapped[int | None]

    # Platform
    platform: Mapped[str] = mapped_column(default="android")  # android | ios
    bundle_id: Mapped[str | None]
    min_ios_version: Mapped[str | None]
    ats_config_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Pipeline state
    status: Mapped[str] = mapped_column(default="pending")
    # pending | decompiling | analyzing | complete | failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    decompile_path: Mapped[str | None]  # path to apktool output dir
    jadx_path: Mapped[str | None]       # path to jadx Java output dir

    findings: Mapped[list["StaticFinding"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    dynamic_sessions: Mapped[list["DynamicSession"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class StaticFinding(Base):
    __tablename__ = "static_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    category: Mapped[str]
    # hardcoded_secret | insecure_config | dangerous_permission | exported_component | manifest_issue
    severity: Mapped[str]
    # critical | high | medium | low | info
    title: Mapped[str]
    description: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str | None]
    line_number: Mapped[int | None]
    evidence: Mapped[str | None] = mapped_column(Text)  # JSON: {"match": "...", "context": "..."}
    rule_id: Mapped[str | None]

    analysis: Mapped["Analysis"] = relationship(back_populates="findings")
