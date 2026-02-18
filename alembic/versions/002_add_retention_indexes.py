"""Add data retention indexes for efficient pruning.

Standalone timestamp indexes enable efficient DELETE of old rows
without requiring device/interface columns in the WHERE clause.

Revision ID: 002
Revises: 001
Create Date: 2026-02-12
"""
from typing import Sequence, Union

from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "idx_metrics_timestamp",
        "traffic_metrics",
        ["timestamp"],
    )
    op.create_index(
        "idx_compliance_created_at",
        "compliance_history",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_compliance_created_at", table_name="compliance_history")
    op.drop_index("idx_metrics_timestamp", table_name="traffic_metrics")
