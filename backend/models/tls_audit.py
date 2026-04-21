from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class TlsAudit(Base):
    __tablename__ = "tls_audits"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    host: Mapped[str]
    port: Mapped[int] = mapped_column(default=443)
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )
    audited_at: Mapped[datetime] = mapped_column(default=func.now())
    status: Mapped[str] = mapped_column(default="ok")  # ok | error

    cert_subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    cert_expiry: Mapped[str | None]
    cert_self_signed: Mapped[bool | None]

    tls10_enabled: Mapped[bool] = mapped_column(default=False)
    tls11_enabled: Mapped[bool] = mapped_column(default=False)
    tls12_enabled: Mapped[bool] = mapped_column(default=False)
    tls13_enabled: Mapped[bool] = mapped_column(default=False)

    hsts_present: Mapped[bool] = mapped_column(default=False)
    weak_ciphers: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON list
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
