"""Feature 2 — detected_libraries and cve_matches tables.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detected_libraries",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("version", sa.String, nullable=True),
        sa.Column("ecosystem", sa.String, nullable=False),
        sa.Column("source", sa.String, nullable=False),
    )
    op.create_index("ix_detected_libraries_analysis_id", "detected_libraries", ["analysis_id"])

    op.create_table(
        "cve_matches",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("library_id", sa.Integer,
                  sa.ForeignKey("detected_libraries.id", ondelete="CASCADE"), nullable=False),
        sa.Column("osv_id", sa.String, nullable=False),
        sa.Column("cve_id", sa.String, nullable=True),
        sa.Column("severity", sa.String, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("fixed_version", sa.String, nullable=True),
        sa.Column("published", sa.String, nullable=True),
        sa.Column("fetched_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_cve_matches_analysis_id", "cve_matches", ["analysis_id"])
    op.create_index("ix_cve_matches_library_id", "cve_matches", ["library_id"])


def downgrade() -> None:
    op.drop_index("ix_cve_matches_library_id", table_name="cve_matches")
    op.drop_index("ix_cve_matches_analysis_id", table_name="cve_matches")
    op.drop_table("cve_matches")
    op.drop_index("ix_detected_libraries_analysis_id", table_name="detected_libraries")
    op.drop_table("detected_libraries")
