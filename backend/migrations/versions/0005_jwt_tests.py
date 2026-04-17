"""Feature 5 — jwt_tests table.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "jwt_tests",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("raw_token", sa.Text, nullable=False),
        sa.Column("decoded_header", sa.Text, nullable=True),
        sa.Column("decoded_payload", sa.Text, nullable=True),
        sa.Column("alg_none_token", sa.Text, nullable=True),
        sa.Column("hmac_secret_found", sa.String, nullable=True),
        sa.Column("rs256_hs256_token", sa.Text, nullable=True),
        sa.Column("kid_injection_payloads", sa.Text, nullable=True),
        sa.Column("role_escalation_tokens", sa.Text, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )
    op.create_index("ix_jwt_tests_session_id", "jwt_tests", ["session_id"])
    op.create_index("ix_jwt_tests_analysis_id", "jwt_tests", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_jwt_tests_analysis_id", table_name="jwt_tests")
    op.drop_index("ix_jwt_tests_session_id", table_name="jwt_tests")
    op.drop_table("jwt_tests")
