"""Feature 9 — brute_force_jobs and brute_force_attempts tables.

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "brute_force_jobs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("auth_type", sa.String, nullable=False, server_default="form"),
        sa.Column("username_field", sa.String, nullable=False, server_default="username"),
        sa.Column("password_field", sa.String, nullable=False, server_default="password"),
        sa.Column("wordlist_path", sa.String, nullable=True),
        sa.Column("username", sa.String, nullable=False),
        sa.Column("concurrency", sa.Integer, nullable=False, server_default="5"),
        sa.Column("rate_limit_rps", sa.Float, nullable=False, server_default="10.0"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("attempts_made", sa.Integer, nullable=False, server_default="0"),
        sa.Column("credentials_found", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )

    op.create_table(
        "brute_force_attempts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.Integer,
                  sa.ForeignKey("brute_force_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("username", sa.String, nullable=False),
        sa.Column("password", sa.String, nullable=False),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("timestamp", sa.DateTime, nullable=False),
    )
    op.create_index("ix_brute_force_attempts_job_id", "brute_force_attempts", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_brute_force_attempts_job_id", table_name="brute_force_attempts")
    op.drop_table("brute_force_attempts")
    op.drop_table("brute_force_jobs")
