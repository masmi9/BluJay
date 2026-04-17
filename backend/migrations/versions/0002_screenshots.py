"""Feature 1 — screenshots table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "screenshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("captured_at", sa.DateTime, nullable=False),
        sa.Column("label", sa.String, nullable=False, server_default=""),
        sa.Column("file_path", sa.String, nullable=False),
        sa.Column("thumbnail_b64", sa.Text, nullable=False),
    )
    op.create_index("ix_screenshots_session_id", "screenshots", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_screenshots_session_id", table_name="screenshots")
    op.drop_table("screenshots")
