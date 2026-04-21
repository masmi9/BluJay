from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, LargeBinary, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

if TYPE_CHECKING:
    from models.analysis import Analysis


class DynamicSession(Base):
    __tablename__ = "dynamic_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    analysis_id: Mapped[int | None] = mapped_column(ForeignKey("analyses.id", ondelete="SET NULL"), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())

    device_serial: Mapped[str]   # ADB serial for Android; UDID for iOS
    package_name: Mapped[str]
    platform: Mapped[str] = mapped_column(default="android")  # android | ios
    status: Mapped[str] = mapped_column(default="active")  # active | stopped
    proxy_port: Mapped[int | None]
    frida_attached: Mapped[bool] = mapped_column(default=False)

    analysis: Mapped["Analysis"] = relationship(back_populates="dynamic_sessions")
    proxy_flows: Mapped[list["ProxyFlow"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    frida_events: Mapped[list["FridaEvent"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class ProxyFlow(Base):
    __tablename__ = "proxy_flows"

    id: Mapped[str] = mapped_column(primary_key=True)  # mitmproxy flow UUID
    session_id: Mapped[int] = mapped_column(ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(default=func.now())

    method: Mapped[str]
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str]
    path: Mapped[str] = mapped_column(Text)
    request_headers: Mapped[str] = mapped_column(Text)   # JSON
    request_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    response_status: Mapped[int | None]
    response_headers: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    response_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    tls: Mapped[bool] = mapped_column(default=False)
    content_type: Mapped[str | None]
    duration_ms: Mapped[float | None]

    session: Mapped["DynamicSession"] = relationship(back_populates="proxy_flows")


class FridaEvent(Base):
    __tablename__ = "frida_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(default=func.now())

    event_type: Mapped[str]  # log | hook_hit | error | send
    script_name: Mapped[str | None]
    payload: Mapped[str] = mapped_column(Text)  # JSON blob

    session: Mapped["DynamicSession"] = relationship(back_populates="frida_events")
