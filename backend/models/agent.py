from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    device_serial: Mapped[str]
    command_type: Mapped[str]   # manifest_analysis | permission_audit | exported_components |
                                 # content_provider | intent_exploit | ipc_analysis | shell
    args: Mapped[str | None] = mapped_column(Text)      # JSON
    result: Mapped[str | None] = mapped_column(Text)    # JSON
    status: Mapped[str] = mapped_column(default="pending")  # pending | running | complete | error
    error: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[float | None]
