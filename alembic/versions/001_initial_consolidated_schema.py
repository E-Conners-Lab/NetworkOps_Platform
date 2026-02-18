"""Initial consolidated schema — all 41 tables from 9 databases.

Revision ID: 001
Revises: None
Create Date: 2026-02-12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # =========================================================================
    # Auth tables (from auth.db / users.db — dashboard/auth/schema.py)
    # =========================================================================

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("username", sa.Text, unique=True, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.Text, server_default="operator"),
        sa.Column("is_active", sa.Integer, server_default="1"),
        sa.Column("failed_attempts", sa.Integer, server_default="0"),
        sa.Column("locked_until", sa.Text),
        sa.Column("password_change_required", sa.Integer, server_default="0"),
        sa.Column("saml_uid", sa.Text, unique=True),
        sa.Column("auth_provider", sa.Text, server_default="local"),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "token_blacklist",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("jti", sa.Text, unique=True, nullable=False),
        sa.Column("expires_at", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text, unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "groups",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text, unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "group_permissions",
        sa.Column("group_id", sa.Integer, sa.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("permission_id", sa.Integer, sa.ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("group_id", "permission_id"),
    )

    op.create_table(
        "user_groups",
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_id", sa.Integer, sa.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("user_id", "group_id"),
    )

    # =========================================================================
    # Session tables (from users.db — dashboard/sessions.py)
    # =========================================================================

    op.create_table(
        "active_sessions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.Text, unique=True, nullable=False),
        sa.Column("access_jti", sa.Text, nullable=False),
        sa.Column("refresh_jti", sa.Text, nullable=False),
        sa.Column("ip_address", sa.Text),
        sa.Column("user_agent", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("last_activity", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_active_sessions_user_id", "active_sessions", ["user_id"])
    op.create_index("idx_active_sessions_access_jti", "active_sessions", ["access_jti"])
    op.create_index("idx_active_sessions_refresh_jti", "active_sessions", ["refresh_jti"])

    # =========================================================================
    # MFA tables (from users.db — dashboard/mfa.py)
    # =========================================================================

    op.create_table(
        "user_mfa",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("totp_secret_encrypted", sa.Text, nullable=False),
        sa.Column("is_enabled", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("confirmed_at", sa.Text),
    )
    op.create_index("idx_user_mfa_user_id", "user_mfa", ["user_id"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.Text, nullable=False),
        sa.Column("is_used", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("used_at", sa.Text),
    )
    op.create_index("idx_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])

    # =========================================================================
    # Quota/Organization tables (from users.db — dashboard/quota.py)
    # =========================================================================

    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text, unique=True, nullable=False),
        sa.Column("slug", sa.Text, unique=True, nullable=False),
        sa.Column("is_active", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "user_organizations",
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("role", sa.Text, nullable=False, server_default="member"),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "organization_quotas",
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id"), primary_key=True),
        sa.Column("monthly_token_limit", sa.Integer, nullable=False, server_default="1000000"),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "token_usage",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("model", sa.Text, nullable=False),
        sa.Column("input_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("billing_period", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_token_usage_org_period", "token_usage", ["organization_id", "billing_period"])

    op.create_table(
        "monthly_usage_summary",
        sa.Column("organization_id", sa.Integer, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("billing_period", sa.Text, nullable=False),
        sa.Column("total_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("request_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_updated", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("organization_id", "billing_period"),
    )

    # =========================================================================
    # Network State tables (from network_state.db — core/unified_db.py)
    # =========================================================================

    op.create_table(
        "snapshots",
        sa.Column("snapshot_id", sa.Text, primary_key=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("ospf_neighbors", sa.Text),
        sa.Column("bgp_peers", sa.Text),
        sa.Column("interfaces", sa.Text),
        sa.Column("route_count", sa.Integer),
        sa.Column("platform", sa.Text),
        sa.Column("is_baseline", sa.Integer, server_default="0"),
        sa.Column("notes", sa.Text),
    )
    op.create_index("idx_snapshots_device", "snapshots", ["device", "timestamp"])
    op.create_index("idx_snapshots_baseline", "snapshots", ["device", "is_baseline"])

    op.create_table(
        "baselines",
        sa.Column("device", sa.Text, primary_key=True),
        sa.Column("snapshot_id", sa.Text, sa.ForeignKey("snapshots.snapshot_id"), nullable=False),
        sa.Column("set_at", sa.Text, nullable=False),
        sa.Column("set_by", sa.Text),
        sa.Column("reason", sa.Text),
    )

    op.create_table(
        "drift_history",
        sa.Column("drift_id", sa.Text, primary_key=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("detected_at", sa.Text, nullable=False),
        sa.Column("drift_type", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("baseline_value", sa.Text),
        sa.Column("current_value", sa.Text),
        sa.Column("details", sa.Text),
        sa.Column("source", sa.Text, server_default="snapshot"),
    )
    op.create_index("idx_drift_device", "drift_history", ["device", "detected_at"])

    op.create_table(
        "traffic_metrics",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text, nullable=False),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("in_octets", sa.Integer),
        sa.Column("out_octets", sa.Integer),
        sa.Column("in_packets", sa.Integer),
        sa.Column("out_packets", sa.Integer),
        sa.Column("in_errors", sa.Integer),
        sa.Column("out_errors", sa.Integer),
        sa.Column("in_discards", sa.Integer),
        sa.Column("out_discards", sa.Integer),
        sa.Column("speed", sa.Integer),
        sa.Column("admin_status", sa.Text),
        sa.Column("oper_status", sa.Text),
        sa.Column("in_bps", sa.Float),
        sa.Column("out_bps", sa.Float),
        sa.Column("in_utilization", sa.Float),
        sa.Column("out_utilization", sa.Float),
    )
    op.create_index("idx_metrics_device_intf", "traffic_metrics", ["device", "interface", "timestamp"])

    op.create_table(
        "traffic_baselines",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text, nullable=False),
        sa.Column("metric", sa.Text, nullable=False),
        sa.Column("samples", sa.Integer),
        sa.Column("mean", sa.Float),
        sa.Column("std_dev", sa.Float),
        sa.Column("min_val", sa.Float),
        sa.Column("max_val", sa.Float),
        sa.Column("p25", sa.Float),
        sa.Column("p50", sa.Float),
        sa.Column("p75", sa.Float),
        sa.Column("p95", sa.Float),
        sa.Column("calculated_at", sa.Text),
        sa.Column("period_days", sa.Integer),
        sa.UniqueConstraint("device", "interface", "metric"),
    )

    op.create_table(
        "anomalies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text, nullable=False),
        sa.Column("anomaly_type", sa.Text, nullable=False),
        sa.Column("metric", sa.Text),
        sa.Column("current_value", sa.Float),
        sa.Column("baseline_mean", sa.Float),
        sa.Column("baseline_std", sa.Float),
        sa.Column("zscore", sa.Float),
        sa.Column("severity", sa.Text),
        sa.Column("detected_at", sa.Text),
        sa.Column("message", sa.Text),
    )
    op.create_index("idx_anomalies_device", "anomalies", ["device", "detected_at"])

    op.create_table(
        "compliance_history",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("template", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("score", sa.Float, nullable=False),
        sa.Column("total_rules", sa.Integer, nullable=False),
        sa.Column("passed_rules", sa.Integer, nullable=False),
        sa.Column("failed_rules", sa.Integer, nullable=False),
        sa.Column("violations_json", sa.Text),
        sa.Column("checked_at", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_compliance_device", "compliance_history", ["device", "checked_at"])

    op.create_table(
        "events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.Text, unique=True, nullable=False),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("subsystem", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("summary", sa.Text, nullable=False),
        sa.Column("details", sa.Text),
        sa.Column("correlated_event_ids", sa.Text),
    )
    op.create_index("idx_events_device", "events", ["device", "timestamp"])
    op.create_index("idx_events_subsystem", "events", ["subsystem", "timestamp"])

    op.create_table(
        "intent_violations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("intent_type", sa.Text, nullable=False),
        sa.Column("intent_key", sa.Text, nullable=False),
        sa.Column("expected_state", sa.Text, nullable=False),
        sa.Column("actual_state", sa.Text),
        sa.Column("violation_severity", sa.Text, nullable=False),
        sa.Column("detected_at", sa.Text, nullable=False),
        sa.Column("resolved_at", sa.Text),
        sa.Column("details", sa.Text),
    )
    op.create_index("idx_intent_device", "intent_violations", ["device", "detected_at"])

    op.create_table(
        "dependency_graph",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("captured_at", sa.Text, nullable=False),
        sa.Column("graph_json", sa.Text, nullable=False),
        sa.Column("node_count", sa.Integer),
        sa.Column("edge_count", sa.Integer),
    )

    # =========================================================================
    # Agent tables (from agent.db — agents/db/models.py)
    # =========================================================================

    op.create_table(
        "agent_decisions",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("symptom", sa.Text, nullable=False),
        sa.Column("symptom_category", sa.Text, nullable=False),
        sa.Column("triggering_event_id", sa.Text, nullable=False),
        sa.Column("reasoning_steps", sa.Text, nullable=False),
        sa.Column("knowledge_base_version", sa.Text, nullable=False),
        sa.Column("proposed_action", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("trace_id", sa.Text, server_default=""),
        sa.Column("validation_result", sa.Text),
        sa.Column("execution_result", sa.Text),
    )
    op.create_index("idx_decisions_status", "agent_decisions", ["status", "created_at"])
    op.create_index("idx_decisions_device", "agent_decisions", ["device", "created_at"])

    op.create_table(
        "human_approvals",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("decision_id", sa.Text, sa.ForeignKey("agent_decisions.id"), nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("blast_radius", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("reviewed_by", sa.Text),
        sa.Column("reviewed_at", sa.Text),
        sa.Column("review_notes", sa.Text),
        sa.Column("expires_at", sa.Text),
    )
    op.create_index("idx_approvals_status", "human_approvals", ["status", "created_at"])

    op.create_table(
        "agent_audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("decision_id", sa.Text),
        sa.Column("device", sa.Text),
        sa.Column("action", sa.Text),
        sa.Column("details", sa.Text, nullable=False),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("trace_id", sa.Text, server_default=""),
    )
    op.create_index("idx_audit_timestamp", "agent_audit_log", ["timestamp"])

    op.create_table(
        "daily_reports",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("report_date", sa.Text, unique=True, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("devices_healthy", sa.Integer, nullable=False),
        sa.Column("devices_degraded", sa.Integer, nullable=False),
        sa.Column("devices_critical", sa.Integer, nullable=False),
        sa.Column("incidents_opened", sa.Integer, nullable=False),
        sa.Column("incidents_closed", sa.Integer, nullable=False),
        sa.Column("agent_decisions_total", sa.Integer, nullable=False),
        sa.Column("agent_decisions_auto_approved", sa.Integer, nullable=False),
        sa.Column("agent_decisions_human_approved", sa.Integer, nullable=False),
        sa.Column("agent_decisions_rejected", sa.Integer, nullable=False),
        sa.Column("compliance_score", sa.Float, nullable=False),
        sa.Column("health_summary", sa.Text, nullable=False),
        sa.Column("pdf_path", sa.Text),
    )

    op.create_table(
        "perceived_events",
        sa.Column("event_id", sa.Text, primary_key=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("symptom", sa.Text, nullable=False),
        sa.Column("symptom_category", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("raw_data", sa.Text),
        sa.Column("processed", sa.Boolean, server_default="0"),
        sa.Column("decision_id", sa.Text),
        sa.Column("trace_id", sa.Text, server_default=""),
    )
    op.create_index("idx_events_processed", "perceived_events", ["processed", "timestamp"])

    # =========================================================================
    # Memory tables (from memory.db — memory/store.py)
    # =========================================================================

    op.create_table(
        "tool_calls",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("tool_name", sa.Text, nullable=False),
        sa.Column("device_name", sa.Text),
        sa.Column("arguments", sa.Text),
        sa.Column("result_summary", sa.Text),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("status", sa.Text, server_default="success"),
    )
    op.create_index("idx_tool_calls_device", "tool_calls", ["device_name"])
    op.create_index("idx_tool_calls_tool", "tool_calls", ["tool_name"])
    op.create_index("idx_tool_calls_ts", "tool_calls", ["timestamp"])

    op.create_table(
        "device_states",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("device_name", sa.Text, nullable=False),
        sa.Column("state_type", sa.Text),
        sa.Column("data", sa.Text),
        sa.Column("label", sa.Text),
    )
    op.create_index("idx_device_states_device", "device_states", ["device_name"])
    op.create_index("idx_device_states_type", "device_states", ["state_type"])

    op.create_table(
        "conversations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("session_id", sa.Text),
        sa.Column("summary", sa.Text),
        sa.Column("tools_used", sa.Text),
        sa.Column("devices_mentioned", sa.Text),
    )
    op.create_index("idx_conversations_ts", "conversations", ["timestamp"])

    op.create_table(
        "feedback",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.Text, nullable=False),
        sa.Column("tool_call_id", sa.Integer, sa.ForeignKey("tool_calls.id")),
        sa.Column("session_id", sa.Text),
        sa.Column("tool_name", sa.Text, nullable=False),
        sa.Column("device_name", sa.Text),
        sa.Column("correct", sa.Boolean, nullable=False),
        sa.Column("error_type", sa.Text),
        sa.Column("original_error", sa.Text),
        sa.Column("correction", sa.Text),
        sa.Column("resolution", sa.Text),
        sa.Column("severity", sa.Text, server_default="medium"),
        sa.Column("learned", sa.Boolean, server_default="0"),
    )
    op.create_index("idx_feedback_tool", "feedback", ["tool_name"])
    op.create_index("idx_feedback_device", "feedback", ["device_name"])
    op.create_index("idx_feedback_error_type", "feedback", ["error_type"])
    op.create_index("idx_feedback_learned", "feedback", ["learned"])

    # =========================================================================
    # Config Tree tables (from config_trees.db — core/config_tree_db.py)
    # =========================================================================

    op.create_table(
        "config_trees",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, unique=True, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("platform", sa.Text, nullable=False, server_default="cisco_ios"),
        sa.Column("version", sa.Text, nullable=False, server_default="1.0"),
        sa.Column("created_by", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_trees_name", "config_trees", ["name"])
    op.create_index("idx_trees_platform", "config_trees", ["platform"])
    op.create_index("idx_trees_created_by", "config_trees", ["created_by"])

    op.create_table(
        "config_tree_nodes",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("tree_id", sa.Text, sa.ForeignKey("config_trees.id", ondelete="CASCADE"), nullable=False),
        sa.Column("parent_id", sa.Text, sa.ForeignKey("config_tree_nodes.id", ondelete="CASCADE")),
        sa.Column("node_type", sa.Text, nullable=False),
        sa.Column("label", sa.Text, nullable=False),
        sa.Column("command_template", sa.Text),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_required", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_repeatable", sa.Integer, nullable=False, server_default="0"),
        sa.Column("validation_regex", sa.Text),
        sa.Column("default_value", sa.Text),
        sa.Column("help_text", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("idx_nodes_tree", "config_tree_nodes", ["tree_id"])
    op.create_index("idx_nodes_parent", "config_tree_nodes", ["parent_id"])
    op.create_index("idx_nodes_sort", "config_tree_nodes", ["tree_id", "parent_id", "sort_order"])

    op.create_table(
        "config_node_variables",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("node_id", sa.Text, sa.ForeignKey("config_tree_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("var_name", sa.Text, nullable=False),
        sa.Column("var_type", sa.Text, nullable=False),
        sa.Column("choices_json", sa.Text),
        sa.Column("validation_regex", sa.Text),
        sa.Column("min_value", sa.Integer),
        sa.Column("max_value", sa.Integer),
        sa.Column("is_required", sa.Integer, nullable=False, server_default="1"),
        sa.Column("default_value", sa.Text),
    )
    op.create_index("idx_vars_node", "config_node_variables", ["node_id"])

    # =========================================================================
    # Playbook tables (from playbooks.db — core/remediation_playbooks.py)
    # =========================================================================

    op.create_table(
        "executions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("execution_id", sa.Text, unique=True, nullable=False),
        sa.Column("playbook_id", sa.Text, nullable=False),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("started_at", sa.Text, nullable=False),
        sa.Column("completed_at", sa.Text),
        sa.Column("parameters", sa.Text),
        sa.Column("step_results", sa.Text),
        sa.Column("rollback_performed", sa.Boolean, server_default="0"),
        sa.Column("dry_run", sa.Boolean, server_default="0"),
    )
    op.create_index("idx_exec_device", "executions", ["device", "started_at"])

    # =========================================================================
    # Change Workflow tables (from changes.db — core/change_workflows.py)
    # =========================================================================

    op.create_table(
        "changes",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("change_type", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("commands_json", sa.Text),
        sa.Column("validation_checks_json", sa.Text),
        sa.Column("rollback_commands_json", sa.Text),
        sa.Column("pre_state_json", sa.Text),
        sa.Column("post_validation_json", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("created_by", sa.Text),
        sa.Column("approved_at", sa.Text),
        sa.Column("approved_by", sa.Text),
        sa.Column("executed_at", sa.Text),
        sa.Column("completed_at", sa.Text),
        sa.Column("error", sa.Text),
        sa.Column("execution_output_json", sa.Text),
        sa.Column("require_approval", sa.Integer, server_default="1"),
        sa.Column("auto_rollback", sa.Integer, server_default="1"),
    )
    op.create_index("idx_changes_device", "changes", ["device", "created_at"])
    op.create_index("idx_changes_status", "changes", ["status"])

    # =========================================================================
    # Capacity Forecast tables (from capacity_forecast.db)
    # =========================================================================

    op.create_table(
        "capacity_metrics",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text),
        sa.Column("metric_type", sa.Text, nullable=False),
        sa.Column("value", sa.Float, nullable=False),
        sa.Column("timestamp", sa.Text, nullable=False),
    )
    op.create_index("idx_capacity_device", "capacity_metrics", ["device", "interface", "metric_type", "timestamp"])

    op.create_table(
        "forecasts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text),
        sa.Column("metric_type", sa.Text, nullable=False),
        sa.Column("forecast_data", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
    )

    op.create_table(
        "recommendations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("device", sa.Text, nullable=False),
        sa.Column("interface", sa.Text),
        sa.Column("metric", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("acknowledged", sa.Boolean, server_default="0"),
    )


def downgrade() -> None:
    # Drop in reverse order of creation (respect foreign keys)
    tables = [
        "recommendations", "forecasts", "capacity_metrics",
        "changes",
        "executions",
        "config_node_variables", "config_tree_nodes", "config_trees",
        "feedback", "conversations", "device_states", "tool_calls",
        "perceived_events",
        "daily_reports", "agent_audit_log", "human_approvals", "agent_decisions",
        "dependency_graph", "intent_violations",
        "events", "compliance_history",
        "anomalies", "traffic_baselines", "traffic_metrics",
        "drift_history", "baselines", "snapshots",
        "monthly_usage_summary", "token_usage", "organization_quotas",
        "user_organizations", "organizations",
        "mfa_recovery_codes", "user_mfa",
        "active_sessions",
        "user_groups", "group_permissions",
        "groups", "permissions", "token_blacklist", "users",
    ]
    for table in tables:
        op.drop_table(table)
