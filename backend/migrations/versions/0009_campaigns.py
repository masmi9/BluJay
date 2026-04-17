"""Feature — campaign_jobs and campaign_targets tables (Multi-APK Campaign).

Revision ID: 0009
Revises: 0008
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaign_jobs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("platform", sa.String, nullable=False, server_default="android"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
    )

    op.create_table(
        "campaign_targets",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("campaign_id", sa.Integer,
                  sa.ForeignKey("campaign_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("apk_filename", sa.String, nullable=False),
        sa.Column("upload_path", sa.String, nullable=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index("ix_campaign_targets_campaign_id", "campaign_targets", ["campaign_id"])
    op.create_index("ix_campaign_targets_analysis_id", "campaign_targets", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_campaign_targets_analysis_id", table_name="campaign_targets")
    op.drop_index("ix_campaign_targets_campaign_id", table_name="campaign_targets")
    op.drop_table("campaign_targets")
    op.drop_table("campaign_jobs")
