from datetime import datetime

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class Screenshot(Base):
    __tablename__ = "screenshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), index=True
    )
    captured_at: Mapped[datetime] = mapped_column(default=func.now())
    label: Mapped[str] = mapped_column(default="")
    file_path: Mapped[str]
    thumbnail_b64: Mapped[str] = mapped_column(Text)
