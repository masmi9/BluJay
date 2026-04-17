"""Feature 6 — analysis_diffs table.

Tracks diffs between two analyses (before/after comparison): added/removed
static findings, permission changes, and severity deltas.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "analysis_diffs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        # baseline = the "before" analysis; target = the "after" analysis
        sa.Column("baseline_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        # diff_type: permissions | findings | libraries | full
        sa.Column("diff_type", sa.String, nullable=False, server_default="full"),
        # JSON lists / objects — nullable so partial diffs are fine
        sa.Column("added_findings", sa.Text, nullable=True),    # JSON list of finding dicts
        sa.Column("removed_findings", sa.Text, nullable=True),  # JSON list of finding dicts
        sa.Column("added_permissions", sa.Text, nullable=True), # JSON list of strings
        sa.Column("removed_permissions", sa.Text, nullable=True),
        sa.Column("severity_delta", sa.Text, nullable=True),    # JSON e.g. {"critical":+2,"high":-1}
        sa.Column("summary", sa.Text, nullable=True),
    )
    op.create_index("ix_analysis_diffs_baseline_id", "analysis_diffs", ["baseline_id"])
    op.create_index("ix_analysis_diffs_target_id", "analysis_diffs", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_analysis_diffs_target_id", table_name="analysis_diffs")
    op.drop_index("ix_analysis_diffs_baseline_id", table_name="analysis_diffs")
    op.drop_table("analysis_diffs")
