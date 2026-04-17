from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class CampaignJob(Base):
    """A named batch job that analyses multiple APKs/IPAs in one run."""
    __tablename__ = "campaign_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    name: Mapped[str]
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform: Mapped[str] = mapped_column(default="android")  # android | ios | mixed
    status: Mapped[str] = mapped_column(default="pending")    # pending | running | complete | failed

    targets: Mapped[list["CampaignTarget"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class CampaignTarget(Base):
    """A single APK/IPA within a campaign."""
    __tablename__ = "campaign_targets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("campaign_jobs.id", ondelete="CASCADE"), index=True
    )
    apk_filename: Mapped[str]
    upload_path: Mapped[str | None]
    # Linked once analysis completes
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    campaign: Mapped["CampaignJob"] = relationship(back_populates="targets")
