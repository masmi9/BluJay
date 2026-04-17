"""Feature 8 — fuzz_jobs and fuzz_results tables.

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "fuzz_jobs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("attacks", sa.Text, nullable=True),
        sa.Column("endpoint_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("result_summary", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index("ix_fuzz_jobs_session_id", "fuzz_jobs", ["session_id"])
    op.create_index("ix_fuzz_jobs_analysis_id", "fuzz_jobs", ["analysis_id"])

    op.create_table(
        "fuzz_results",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.Integer,
                  sa.ForeignKey("fuzz_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("attack_type", sa.String, nullable=False),
        sa.Column("method", sa.String, nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
        sa.Column("is_interesting", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_fuzz_results_job_id", "fuzz_results", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_fuzz_results_job_id", table_name="fuzz_results")
    op.drop_table("fuzz_results")
    op.drop_index("ix_fuzz_jobs_analysis_id", table_name="fuzz_jobs")
    op.drop_index("ix_fuzz_jobs_session_id", table_name="fuzz_jobs")
    op.drop_table("fuzz_jobs")
