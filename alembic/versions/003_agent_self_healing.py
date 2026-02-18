"""Add agent self-healing columns and rate limiter state table.

Adds escalation tracking, audit integrity hashing, enhanced
reporting columns, and persistent rate limiter state.

Revision ID: 003
Revises: 002
Create Date: 2026-02-12
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- agent_decisions: escalation tracking --
    with op.batch_alter_table("agent_decisions") as batch_op:
        batch_op.add_column(
            sa.Column("parent_decision_id", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("escalation_level", sa.Integer(), server_default="0", nullable=False)
        )

    # -- agent_audit_log: tamper-evident hash chain --
    with op.batch_alter_table("agent_audit_log") as batch_op:
        batch_op.add_column(
            sa.Column("integrity_hash", sa.Text(), nullable=True)
        )

    # -- daily_reports: enhanced reporting --
    with op.batch_alter_table("daily_reports") as batch_op:
        batch_op.add_column(sa.Column("trend_data", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("anomalies", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("escalation_count", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.add_column(
            sa.Column("mean_time_to_remediate", sa.Float(), server_default="0.0", nullable=False)
        )

    # -- New table: agent_rate_limiter_state --
    op.create_table(
        "agent_rate_limiter_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("key", sa.Text(), nullable=False, unique=True),
        sa.Column("timestamps", sa.Text(), nullable=False),  # JSON array of floats
        sa.Column("updated_at", sa.Text(), nullable=False),
    )

    # -- Indexes --
    op.create_index(
        "idx_decisions_parent", "agent_decisions", ["parent_decision_id"]
    )
    op.create_index(
        "idx_decisions_created_at", "agent_decisions", ["created_at"]
    )
    op.create_index(
        "idx_audit_created_at", "agent_audit_log", ["timestamp"]
    )
    op.create_index(
        "idx_events_created_at", "perceived_events", ["timestamp"]
    )


def downgrade() -> None:
    op.drop_index("idx_events_created_at", table_name="perceived_events")
    op.drop_index("idx_audit_created_at", table_name="agent_audit_log")
    op.drop_index("idx_decisions_created_at", table_name="agent_decisions")
    op.drop_index("idx_decisions_parent", table_name="agent_decisions")
    op.drop_table("agent_rate_limiter_state")

    with op.batch_alter_table("daily_reports") as batch_op:
        batch_op.drop_column("mean_time_to_remediate")
        batch_op.drop_column("escalation_count")
        batch_op.drop_column("anomalies")
        batch_op.drop_column("trend_data")

    with op.batch_alter_table("agent_audit_log") as batch_op:
        batch_op.drop_column("integrity_hash")

    with op.batch_alter_table("agent_decisions") as batch_op:
        batch_op.drop_column("escalation_level")
        batch_op.drop_column("parent_decision_id")
