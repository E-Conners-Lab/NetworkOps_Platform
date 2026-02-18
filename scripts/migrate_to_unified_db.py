#!/usr/bin/env python3
"""
Migrate separate SQLite databases into the unified network_state.db.

Copies rows from:
- data/impact_trending.db (snapshots, baselines, drift_history)
- data/compliance.db (compliance_history)
- data/traffic_baseline.db (traffic_metrics, baselines->traffic_baselines, anomalies)

After migration, originals are renamed to *.db.migrated.

Usage:
    python scripts/migrate_to_unified_db.py
"""

import os
import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.unified_db import UnifiedDB

DATA_DIR = Path(__file__).parent.parent / "data"

IMPACT_DB = DATA_DIR / "impact_trending.db"
COMPLIANCE_DB = DATA_DIR / "compliance.db"
TRAFFIC_DB = DATA_DIR / "traffic_baseline.db"


def migrate_impact_trending(unified_conn: sqlite3.Connection) -> dict:
    """Migrate impact_trending.db tables."""
    counts = {"snapshots": 0, "baselines": 0, "drift_history": 0}

    if not IMPACT_DB.exists():
        print(f"  Skipping {IMPACT_DB.name} (does not exist)")
        return counts

    with sqlite3.connect(IMPACT_DB) as src:
        src.row_factory = sqlite3.Row

        # Migrate snapshots
        rows = src.execute("SELECT * FROM snapshots").fetchall()
        for row in rows:
            try:
                unified_conn.execute("""
                    INSERT OR IGNORE INTO snapshots
                    (snapshot_id, device, timestamp, ospf_neighbors, bgp_peers,
                     interfaces, route_count, platform, is_baseline, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["snapshot_id"], row["device"], row["timestamp"],
                    row["ospf_neighbors"], row["bgp_peers"], row["interfaces"],
                    row["route_count"], row["platform"], row["is_baseline"],
                    row["notes"],
                ))
                counts["snapshots"] += 1
            except Exception as e:
                print(f"  Warning: skipping snapshot {row['snapshot_id']}: {e}")

        # Migrate baselines
        rows = src.execute("SELECT * FROM baselines").fetchall()
        for row in rows:
            try:
                unified_conn.execute("""
                    INSERT OR IGNORE INTO baselines
                    (device, snapshot_id, set_at, set_by, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    row["device"], row["snapshot_id"], row["set_at"],
                    row["set_by"], row["reason"],
                ))
                counts["baselines"] += 1
            except Exception as e:
                print(f"  Warning: skipping baseline for {row['device']}: {e}")

        # Migrate drift_history
        rows = src.execute("SELECT * FROM drift_history").fetchall()
        for row in rows:
            try:
                unified_conn.execute("""
                    INSERT OR IGNORE INTO drift_history
                    (drift_id, device, detected_at, drift_type, severity,
                     description, baseline_value, current_value, details, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["drift_id"], row["device"], row["detected_at"],
                    row["drift_type"], row["severity"], row["description"],
                    row["baseline_value"], row["current_value"], row["details"],
                    "snapshot",
                ))
                counts["drift_history"] += 1
            except Exception as e:
                print(f"  Warning: skipping drift {row['drift_id']}: {e}")

    return counts


def migrate_compliance(unified_conn: sqlite3.Connection) -> dict:
    """Migrate compliance.db tables."""
    counts = {"compliance_history": 0}

    if not COMPLIANCE_DB.exists():
        print(f"  Skipping {COMPLIANCE_DB.name} (does not exist)")
        return counts

    with sqlite3.connect(COMPLIANCE_DB) as src:
        src.row_factory = sqlite3.Row

        rows = src.execute("SELECT * FROM compliance_history").fetchall()
        for row in rows:
            try:
                unified_conn.execute("""
                    INSERT INTO compliance_history
                    (device, template, status, score, total_rules, passed_rules,
                     failed_rules, violations_json, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["device"], row["template"], row["status"], row["score"],
                    row["total_rules"], row["passed_rules"], row["failed_rules"],
                    row["violations_json"], row["checked_at"],
                ))
                counts["compliance_history"] += 1
            except Exception as e:
                print(f"  Warning: skipping compliance record: {e}")

    return counts


def migrate_traffic_baseline(unified_conn: sqlite3.Connection) -> dict:
    """Migrate traffic_baseline.db tables."""
    counts = {"traffic_metrics": 0, "traffic_baselines": 0, "anomalies": 0}

    if not TRAFFIC_DB.exists():
        print(f"  Skipping {TRAFFIC_DB.name} (does not exist)")
        return counts

    with sqlite3.connect(TRAFFIC_DB) as src:
        src.row_factory = sqlite3.Row

        # Migrate traffic_metrics
        rows = src.execute("SELECT * FROM traffic_metrics").fetchall()
        for row in rows:
            try:
                unified_conn.execute("""
                    INSERT INTO traffic_metrics
                    (device, interface, timestamp, in_octets, out_octets,
                     in_packets, out_packets, in_errors, out_errors,
                     in_discards, out_discards, speed, admin_status, oper_status,
                     in_bps, out_bps, in_utilization, out_utilization)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["device"], row["interface"], row["timestamp"],
                    row["in_octets"], row["out_octets"],
                    row["in_packets"], row["out_packets"],
                    row["in_errors"], row["out_errors"],
                    row["in_discards"], row["out_discards"],
                    row["speed"], row["admin_status"], row["oper_status"],
                    row["in_bps"], row["out_bps"],
                    row["in_utilization"], row["out_utilization"],
                ))
                counts["traffic_metrics"] += 1
            except Exception as e:
                print(f"  Warning: skipping traffic metric: {e}")

        # Migrate baselines -> traffic_baselines
        try:
            rows = src.execute("SELECT * FROM baselines").fetchall()
            for row in rows:
                try:
                    unified_conn.execute("""
                        INSERT OR IGNORE INTO traffic_baselines
                        (device, interface, metric, samples, mean, std_dev,
                         min_val, max_val, p25, p50, p75, p95, calculated_at, period_days)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["device"], row["interface"], row["metric"],
                        row["samples"], row["mean"], row["std_dev"],
                        row["min_val"], row["max_val"],
                        row["p25"], row["p50"], row["p75"], row["p95"],
                        row["calculated_at"], row["period_days"],
                    ))
                    counts["traffic_baselines"] += 1
                except Exception as e:
                    print(f"  Warning: skipping traffic baseline: {e}")
        except sqlite3.OperationalError:
            print("  No baselines table in traffic_baseline.db")

        # Migrate anomalies
        try:
            rows = src.execute("SELECT * FROM anomalies").fetchall()
            for row in rows:
                try:
                    unified_conn.execute("""
                        INSERT INTO anomalies
                        (device, interface, anomaly_type, metric, current_value,
                         baseline_mean, baseline_std, zscore, severity, detected_at, message)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["device"], row["interface"], row["anomaly_type"],
                        row["metric"], row["current_value"],
                        row["baseline_mean"], row["baseline_std"], row["zscore"],
                        row["severity"], row["detected_at"], row["message"],
                    ))
                    counts["anomalies"] += 1
                except Exception as e:
                    print(f"  Warning: skipping anomaly: {e}")
        except sqlite3.OperationalError:
            print("  No anomalies table in traffic_baseline.db")

    return counts


def rename_old_dbs():
    """Rename old DB files to *.db.migrated."""
    for db_path in [IMPACT_DB, COMPLIANCE_DB, TRAFFIC_DB]:
        if db_path.exists():
            migrated_path = db_path.with_suffix(".db.migrated")
            if migrated_path.exists():
                print(f"  {migrated_path.name} already exists, skipping rename")
                continue
            db_path.rename(migrated_path)
            print(f"  Renamed {db_path.name} -> {migrated_path.name}")


def main():
    print("=" * 60)
    print("Unified Database Migration")
    print("=" * 60)

    # Create unified DB with full schema
    print(f"\nCreating unified database at {DATA_DIR / 'network_state.db'}")
    db = UnifiedDB(DATA_DIR / "network_state.db")

    with db.connect() as conn:
        # Migrate impact trending
        print("\nMigrating impact_trending.db...")
        impact_counts = migrate_impact_trending(conn)
        for table, count in impact_counts.items():
            print(f"  {table}: {count} rows")

        # Migrate compliance
        print("\nMigrating compliance.db...")
        compliance_counts = migrate_compliance(conn)
        for table, count in compliance_counts.items():
            print(f"  {table}: {count} rows")

        # Migrate traffic baseline
        print("\nMigrating traffic_baseline.db...")
        traffic_counts = migrate_traffic_baseline(conn)
        for table, count in traffic_counts.items():
            print(f"  {table}: {count} rows")

        conn.commit()

    # Verify
    print("\nVerification:")
    with db.connect() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        print(f"  Tables created: {[t[0] for t in tables]}")

        for table_name in [t[0] for t in tables]:
            count = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            print(f"  {table_name}: {count} rows")

    # Rename old databases
    print("\nRenaming old databases...")
    rename_old_dbs()

    print("\nMigration complete.")


if __name__ == "__main__":
    main()
