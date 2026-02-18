#!/usr/bin/env python3
"""
Migrate data from 8 separate SQLite databases into the consolidated networkops.db.

Usage:
    python scripts/migrate_to_consolidated_db.py --check      # Preview what would be migrated
    python scripts/migrate_to_consolidated_db.py --dry-run     # Migrate inside a transaction then rollback
    python scripts/migrate_to_consolidated_db.py --migrate     # Actually migrate data

Excluded: scheduler.db (APScheduler manages its own schema).
"""

import argparse
import logging
import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
DASHBOARD_DATA_DIR = Path(__file__).parent.parent / "dashboard" / "data"
TARGET_DB = DATA_DIR / "networkops.db"

# Source databases and their tables (in FK-safe order within each DB)
SOURCE_DATABASES = {
    "network_state.db": {
        "path": DATA_DIR / "network_state.db",
        "tables": [
            "snapshots", "baselines", "drift_history",
            "traffic_metrics", "traffic_baselines", "anomalies",
            "compliance_history", "events", "intent_violations",
            "dependency_graph",
        ],
    },
    "agent.db": {
        "path": DATA_DIR / "agent.db",
        "tables": [
            "agent_decisions", "human_approvals", "agent_audit_log",
            "daily_reports", "perceived_events",
        ],
    },
    "memory.db": {
        "path": DATA_DIR / "memory.db",
        "tables": [
            "tool_calls", "device_states", "conversations", "feedback",
        ],
    },
    "auth.db": {
        "path": DATA_DIR / "auth.db",
        "tables": [
            "users", "token_blacklist", "permissions", "groups",
            "group_permissions", "user_groups",
        ],
    },
    "users.db": {
        "path": DATA_DIR / "users.db",
        "tables": [
            # Auth tables may overlap with auth.db — INSERT OR IGNORE handles dupes
            "users", "token_blacklist", "permissions", "groups",
            "group_permissions", "user_groups",
            # Session/MFA tables
            "active_sessions", "user_mfa", "mfa_recovery_codes",
            # Quota tables (may not exist)
            "organizations", "user_organizations", "organization_quotas",
            "token_usage", "monthly_usage_summary",
        ],
    },
    "changes.db": {
        "path": DATA_DIR / "changes.db",
        "tables": ["changes"],
    },
    "config_trees.db": {
        "path": DATA_DIR / "config_trees.db",
        "tables": ["config_trees", "config_tree_nodes", "config_node_variables"],
    },
    "playbooks.db": {
        "path": DATA_DIR / "playbooks.db",
        "tables": ["executions"],
    },
    "capacity_forecast.db": {
        "path": DATA_DIR / "capacity_forecast.db",
        "tables": ["capacity_metrics", "forecasts", "recommendations"],
    },
}

# Global FK ordering — tables that MUST be migrated first
FK_ORDER = [
    # Auth tables first (users referenced by many others)
    "users", "token_blacklist", "permissions", "groups",
    "group_permissions", "user_groups",
    # Organization tables
    "organizations", "user_organizations", "organization_quotas",
    "token_usage", "monthly_usage_summary",
    # Session/MFA
    "active_sessions", "user_mfa", "mfa_recovery_codes",
    # Network state
    "snapshots", "baselines", "drift_history",
    "traffic_metrics", "traffic_baselines", "anomalies",
    "compliance_history", "events", "intent_violations", "dependency_graph",
    # Agent
    "agent_decisions", "human_approvals", "agent_audit_log",
    "daily_reports", "perceived_events",
    # Memory
    "tool_calls", "device_states", "conversations", "feedback",
    # Config trees
    "config_trees", "config_tree_nodes", "config_node_variables",
    # Playbooks
    "executions",
    # Changes
    "changes",
    # Capacity
    "capacity_metrics", "forecasts", "recommendations",
]


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Check if a table exists in the database."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _row_count(conn: sqlite3.Connection, table: str) -> int:
    """Get row count for a table."""
    if not _table_exists(conn, table):
        return -1
    return conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]


def _get_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Get column names for a table."""
    rows = conn.execute(f"PRAGMA table_info([{table}])").fetchall()
    return [r[1] for r in rows]


def check_mode():
    """Preview what would be migrated."""
    if not TARGET_DB.exists():
        logger.error(f"Target database not found: {TARGET_DB}")
        logger.error("Run 'alembic upgrade head' first to create the schema.")
        return False

    target_conn = sqlite3.connect(str(TARGET_DB))
    total_rows = 0
    issues = []

    for db_name, info in SOURCE_DATABASES.items():
        src_path = info["path"]
        if not src_path.exists():
            logger.info(f"  {db_name}: not found (skip)")
            continue

        src_conn = sqlite3.connect(str(src_path))
        logger.info(f"\n  {db_name}:")

        for table in info["tables"]:
            src_count = _row_count(src_conn, table)
            if src_count < 0:
                logger.info(f"    {table}: table missing in source (skip)")
                continue
            if src_count == 0:
                logger.info(f"    {table}: 0 rows (skip)")
                continue

            tgt_count = _row_count(target_conn, table)
            if tgt_count < 0:
                issues.append(f"{table}: missing in target DB")
                logger.warning(f"    {table}: {src_count} rows — MISSING in target!")
                continue

            logger.info(f"    {table}: {src_count} source rows, {tgt_count} target rows")
            total_rows += src_count

        src_conn.close()

    target_conn.close()

    logger.info(f"\nTotal rows to migrate: {total_rows}")
    if issues:
        logger.warning(f"Issues found: {len(issues)}")
        for issue in issues:
            logger.warning(f"  - {issue}")
        return False
    return True


def migrate_mode(dry_run: bool = False):
    """Migrate data from source databases to consolidated DB."""
    if not TARGET_DB.exists():
        logger.error(f"Target database not found: {TARGET_DB}")
        logger.error("Run 'alembic upgrade head' first to create the schema.")
        return False

    target_conn = sqlite3.connect(str(TARGET_DB))
    target_conn.execute("PRAGMA journal_mode=WAL")
    target_conn.execute("PRAGMA foreign_keys=OFF")  # Defer FK checks during bulk load

    migrated_tables = set()
    total_migrated = 0
    total_skipped = 0

    try:
        # Process tables in FK order
        for table in FK_ORDER:
            if table in migrated_tables:
                continue

            # Find the source DB for this table
            for db_name, info in SOURCE_DATABASES.items():
                if table not in info["tables"]:
                    continue

                src_path = info["path"]
                if not src_path.exists():
                    continue

                src_conn = sqlite3.connect(str(src_path))
                src_count = _row_count(src_conn, table)

                if src_count <= 0:
                    src_conn.close()
                    continue

                if not _table_exists(target_conn, table):
                    logger.warning(f"  {table}: missing in target, skipping")
                    src_conn.close()
                    continue

                # Get common columns between source and target
                src_cols = set(_get_columns(src_conn, table))
                tgt_cols = set(_get_columns(target_conn, table))
                common_cols = sorted(src_cols & tgt_cols)

                if not common_cols:
                    logger.warning(f"  {table}: no common columns, skipping")
                    src_conn.close()
                    continue

                cols_str = ", ".join(f"[{c}]" for c in common_cols)
                placeholders = ", ".join("?" for _ in common_cols)

                # Read all rows from source
                rows = src_conn.execute(f"SELECT {cols_str} FROM [{table}]").fetchall()
                src_conn.close()

                # Insert into target with INSERT OR IGNORE for duplicate handling
                inserted = 0
                skipped = 0
                for row in rows:
                    try:
                        target_conn.execute(
                            f"INSERT OR IGNORE INTO [{table}] ({cols_str}) VALUES ({placeholders})",
                            tuple(row),
                        )
                        if target_conn.total_changes:
                            inserted += 1
                    except sqlite3.IntegrityError as e:
                        skipped += 1
                        if skipped <= 5:
                            logger.debug(f"  {table}: skipped row — {e}")

                total_migrated += inserted
                total_skipped += skipped
                logger.info(f"  {table}: {inserted} inserted, {skipped} skipped (from {db_name})")
                migrated_tables.add(table)
                break  # Move to next table in FK_ORDER

        if dry_run:
            logger.info("\n[DRY RUN] Rolling back all changes.")
            target_conn.rollback()
        else:
            # Enable FK checks and verify
            target_conn.execute("PRAGMA foreign_keys=ON")
            fk_check = target_conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_check:
                logger.warning(f"\nFK violations found: {len(fk_check)}")
                for violation in fk_check[:10]:
                    logger.warning(f"  table={violation[0]}, rowid={violation[1]}, "
                                   f"references={violation[2]}, fk_index={violation[3]}")
            target_conn.commit()
            logger.info(f"\nMigration complete: {total_migrated} rows inserted, "
                        f"{total_skipped} duplicates skipped.")

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        target_conn.rollback()
        return False
    finally:
        target_conn.close()

    return True


def main():
    parser = argparse.ArgumentParser(description="Migrate to consolidated database")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="Preview what would be migrated")
    group.add_argument("--dry-run", action="store_true", help="Migrate then rollback")
    group.add_argument("--migrate", action="store_true", help="Actually migrate data")
    args = parser.parse_args()

    if args.check:
        check_mode()
    elif args.dry_run:
        migrate_mode(dry_run=True)
    elif args.migrate:
        migrate_mode(dry_run=False)


if __name__ == "__main__":
    main()
