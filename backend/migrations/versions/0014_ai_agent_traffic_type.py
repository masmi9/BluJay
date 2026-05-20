"""AI agent scanner tables + proxy traffic_type column.

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add traffic_type to proxy_flows
    with op.batch_alter_table("proxy_flows") as batch:
        batch.add_column(sa.Column("traffic_type", sa.String(), nullable=True))

    # Create ai_agent_scans
    op.create_table(
        "ai_agent_scans",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("target_url", sa.String(), nullable=False),
        sa.Column("protocol_type", sa.String(), nullable=False),
        sa.Column("probe_categories", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("findings_json", sa.Text(), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # Create ai_agent_findings
    op.create_table(
        "ai_agent_findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("ai_agent_scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("probe_id", sa.String(), nullable=False),
        sa.Column("request_payload", sa.Text(), nullable=True),
        sa.Column("raw_response", sa.Text(), nullable=True),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ai_agent_findings")
    op.drop_table("ai_agent_scans")
    with op.batch_alter_table("proxy_flows") as batch:
        batch.drop_column("traffic_type")
