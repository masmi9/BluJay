"""Feature — PCI payment flow testing: flow_steps_json + flow_steps_count columns.

Revision ID: 0013
Revises: 0012
Create Date: 2026-04-24
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("pci_scan_jobs") as batch:
        batch.add_column(sa.Column("flow_steps_json",  sa.Text(),    nullable=True))
        batch.add_column(sa.Column("flow_steps_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("pci_scan_jobs") as batch:
        batch.drop_column("flow_steps_count")
        batch.drop_column("flow_steps_json")
