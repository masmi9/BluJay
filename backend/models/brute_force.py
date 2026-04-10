from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class BruteForceJob(Base):
    __tablename__ = "brute_force_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    target_url: Mapped[str] = mapped_column(Text)
    auth_type: Mapped[str] = mapped_column(default="form")   # form | json | basic
    username_field: Mapped[str] = mapped_column(default="username")
    password_field: Mapped[str] = mapped_column(default="password")
    wordlist_path: Mapped[str | None]
    username: Mapped[str]
    concurrency: Mapped[int] = mapped_column(default=5)
    rate_limit_rps: Mapped[float] = mapped_column(default=10.0)
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | paused | complete | error
    attempts_made: Mapped[int] = mapped_column(default=0)
    credentials_found: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    attempts: Mapped[list["BruteForceAttempt"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class BruteForceAttempt(Base):
    __tablename__ = "brute_force_attempts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("brute_force_jobs.id", ondelete="CASCADE"), index=True)
    username: Mapped[str]
    password: Mapped[str]
    status_code: Mapped[int | None]
    success: Mapped[bool] = mapped_column(default=False)
    timestamp: Mapped[datetime] = mapped_column(default=func.now())

    job: Mapped["BruteForceJob"] = relationship(back_populates="attempts")
