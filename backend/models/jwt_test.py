from datetime import datetime
from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from database import Base

class JwtTest(Base):
    __tablename__ = "jwt_tests"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True, index=True
    )

    raw_token: Mapped[str] = mapped_column(Text)
    decoded_header: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON
    decoded_payload: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    alg_none_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    hmac_secret_found: Mapped[str | None]  # secret string if found
    rs256_hs256_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    kid_injection_payloads: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    role_escalation_tokens: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
