"""Tests for core/unified_db.py - Unified database layer."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from core.unified_db import UnifiedDB


@pytest.fixture
def tmp_db(consolidated_db):
    """Create a UnifiedDB backed by the consolidated test DB."""
    db = UnifiedDB.get_instance()
    yield db


class TestUnifiedDB:
    """Tests for UnifiedDB schema and connection."""

    def test_creates_database_file(self, tmp_db):
        assert tmp_db.db_path.exists()

    def test_wal_mode_enabled(self, tmp_db):
        with tmp_db.connect() as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode == "wal"

    def test_foreign_keys_enabled(self, tmp_db):
        with tmp_db.connect() as conn:
            fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            assert fk == 1

    def test_all_tables_created(self, tmp_db):
        expected_tables = {
            "snapshots",
            "baselines",
            "drift_history",
            "traffic_metrics",
            "traffic_baselines",
            "anomalies",
            "compliance_history",
            "events",
            "intent_violations",
            "dependency_graph",
        }
        with tmp_db.connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            tables = {row[0] for row in rows}

        assert expected_tables.issubset(tables)

    def test_drift_history_has_source_column(self, tmp_db):
        with tmp_db.connect() as conn:
            conn.execute(
                "INSERT INTO drift_history "
                "(drift_id, device, detected_at, drift_type, severity, source) "
                "VALUES ('d1', 'R1', '2025-01-01', 'test', 'info', 'intent')"
            )
            row = conn.execute(
                "SELECT source FROM drift_history WHERE drift_id = 'd1'"
            ).fetchone()
            assert row[0] == "intent"

    def test_events_table_insert(self, tmp_db):
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO events
                (event_id, timestamp, subsystem, device, event_type, severity, summary)
                VALUES ('e1', '2025-01-01', 'drift', 'R1', 'test', 'info', 'test event')
            """)
            conn.commit()
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            assert count == 1

    def test_intent_violations_table_insert(self, tmp_db):
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 violation_severity, detected_at)
                VALUES ('R3', 'bgp_peer', '172.20.20.5', 'Established',
                        'critical', '2025-01-01')
            """)
            conn.commit()
            count = conn.execute(
                "SELECT COUNT(*) FROM intent_violations"
            ).fetchone()[0]
            assert count == 1

    def test_dependency_graph_table_insert(self, tmp_db):
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO dependency_graph
                (captured_at, graph_json, node_count, edge_count)
                VALUES ('2025-01-01', '{}', 10, 20)
            """)
            conn.commit()
            count = conn.execute(
                "SELECT COUNT(*) FROM dependency_graph"
            ).fetchone()[0]
            assert count == 1

    def test_singleton_returns_same_instance(self, tmp_path):
        db_path = tmp_path / "singleton_test.db"
        UnifiedDB.reset_instance()
        try:
            a = UnifiedDB.get_instance(db_path)
            b = UnifiedDB.get_instance()
            assert a is b
        finally:
            UnifiedDB.reset_instance()

    def test_reset_instance_clears_singleton(self, tmp_path):
        db_path = tmp_path / "reset_test.db"
        UnifiedDB.reset_instance()
        a = UnifiedDB.get_instance(db_path)
        UnifiedDB.reset_instance()
        b = UnifiedDB.get_instance(db_path)
        assert a is not b
        UnifiedDB.reset_instance()

    def test_traffic_baselines_unique_constraint(self, tmp_db):
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO traffic_baselines
                (device, interface, metric, samples, mean, std_dev,
                 min_val, max_val, p25, p50, p75, p95, calculated_at, period_days)
                VALUES ('R1', 'Gi1', 'in_util', 100, 50.0, 10.0,
                        0.0, 100.0, 25.0, 50.0, 75.0, 95.0, '2025-01-01', 7)
            """)
            conn.commit()

            # Same device/interface/metric should replace
            conn.execute("""
                INSERT OR REPLACE INTO traffic_baselines
                (device, interface, metric, samples, mean, std_dev,
                 min_val, max_val, p25, p50, p75, p95, calculated_at, period_days)
                VALUES ('R1', 'Gi1', 'in_util', 200, 55.0, 12.0,
                        0.0, 100.0, 30.0, 55.0, 80.0, 96.0, '2025-01-02', 7)
            """)
            conn.commit()

            count = conn.execute(
                "SELECT COUNT(*) FROM traffic_baselines "
                "WHERE device='R1' AND interface='Gi1' AND metric='in_util'"
            ).fetchone()[0]
            assert count == 1
