"""Feature 4 — tls_audits table.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-17
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tls_audits",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("host", sa.String, nullable=False),
        sa.Column("port", sa.Integer, nullable=False, server_default="443"),
        sa.Column("session_id", sa.Integer,
                  sa.ForeignKey("dynamic_sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("analysis_id", sa.Integer,
                  sa.ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("audited_at", sa.DateTime, nullable=False),
        sa.Column("status", sa.String, nullable=False, server_default="ok"),
        sa.Column("cert_subject", sa.Text, nullable=True),
        sa.Column("cert_issuer", sa.Text, nullable=True),
        sa.Column("cert_expiry", sa.String, nullable=True),
        sa.Column("cert_self_signed", sa.Boolean, nullable=True),
        sa.Column("tls10_enabled", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("tls11_enabled", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("tls12_enabled", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("tls13_enabled", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("hsts_present", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("weak_ciphers", sa.Text, nullable=True),
        sa.Column("findings_json", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )
    op.create_index("ix_tls_audits_session_id", "tls_audits", ["session_id"])
    op.create_index("ix_tls_audits_analysis_id", "tls_audits", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_tls_audits_analysis_id", table_name="tls_audits")
    op.drop_index("ix_tls_audits_session_id", table_name="tls_audits")
    op.drop_table("tls_audits")
