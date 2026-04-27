"""Feature — PCI v2: full scan engine columns (scope, phases, network stats, reports).

Revision ID: 0012
Revises: 0011
Create Date: 2026-04-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── pci_scan_jobs new columns ─────────────────────────────────────────────
    with op.batch_alter_table("pci_scan_jobs") as batch:
        batch.add_column(sa.Column("scope_config",     sa.Text(),    nullable=True))
        batch.add_column(sa.Column("scan_profile",     sa.String(),  nullable=False, server_default="web_only"))
        batch.add_column(sa.Column("phase",            sa.String(),  nullable=True))
        batch.add_column(sa.Column("hosts_found",      sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("ports_open",       sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("pages_crawled",    sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("report_json",      sa.Text(),    nullable=True))
        batch.add_column(sa.Column("report_html_exec", sa.Text(),    nullable=True))
        batch.add_column(sa.Column("report_html_tech", sa.Text(),    nullable=True))

    # ── pci_findings new columns ──────────────────────────────────────────────
    with op.batch_alter_table("pci_findings") as batch:
        batch.add_column(sa.Column("phase",         sa.String(),  nullable=True))
        batch.add_column(sa.Column("evidence_json", sa.Text(),    nullable=True))
        batch.add_column(sa.Column("port",          sa.Integer(), nullable=True))
        batch.add_column(sa.Column("service",       sa.String(),  nullable=True))
        batch.add_column(sa.Column("cvss_score",    sa.Float(),   nullable=True))
        batch.add_column(sa.Column("cve_ids",       sa.Text(),    nullable=True))
        batch.add_column(sa.Column("plugin_id",     sa.String(),  nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("pci_findings") as batch:
        for col in ["plugin_id", "cve_ids", "cvss_score", "service", "port", "evidence_json", "phase"]:
            batch.drop_column(col)

    with op.batch_alter_table("pci_scan_jobs") as batch:
        for col in ["report_html_tech", "report_html_exec", "report_json",
                    "pages_crawled", "ports_open", "hosts_found", "phase",
                    "scan_profile", "scope_config"]:
            batch.drop_column(col)
