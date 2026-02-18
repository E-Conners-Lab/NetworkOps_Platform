"""
Tests for automation metrics collection and persistence.
"""

import pytest
import json
import threading
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

from core.metrics import (
    TestMetrics, ParserMetrics, TestOutcome,
    CorrelationContext, correlation,
    test_metrics, parser_metrics,
    save_all_metrics, load_all_metrics
)


class TestCorrelationContext:
    """Tests for correlation ID management"""

    def test_generate_creates_unique_ids(self):
        """Each call to generate should create a unique ID"""
        ctx = CorrelationContext()
        id1 = ctx.generate()
        id2 = ctx.generate()

        assert id1 != id2
        assert id1.startswith("run-")
        assert id2.startswith("run-")

    def test_context_manager_sets_id(self):
        """Context manager should set and clear correlation ID"""
        ctx = CorrelationContext()

        assert ctx.get() is None

        with ctx.context() as run_id:
            assert ctx.get() == run_id
            assert run_id.startswith("run-")

        assert ctx.get() is None

    def test_manual_set_and_get(self):
        """Manual set/get should work"""
        ctx = CorrelationContext()

        ctx.set("custom-id-123")
        assert ctx.get() == "custom-id-123"

        ctx.clear()
        assert ctx.get() is None

    def test_nested_contexts(self):
        """Nested contexts should maintain proper scope"""
        ctx = CorrelationContext()

        with ctx.context() as outer_id:
            assert ctx.get() == outer_id

            # Inner context replaces outer
            with ctx.context() as inner_id:
                assert ctx.get() == inner_id
                assert inner_id != outer_id

            # After inner exits, context is cleared
            assert ctx.get() is None


class TestTestMetrics:
    """Tests for test execution metrics"""

    def test_record_run_updates_counters(self):
        """Recording a run should update all counters"""
        metrics = TestMetrics()

        metrics.record_run(TestOutcome.PASSED, duration_ms=100.0, test_name="test_example")

        assert metrics.total_runs == 1
        assert metrics.outcomes["passed"] == 1
        assert len(metrics.durations_ms) == 1
        assert metrics.durations_ms[0] == 100.0

    def test_multiple_outcomes(self):
        """Different outcomes should be tracked separately"""
        metrics = TestMetrics()

        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.PASSED, 110.0)
        metrics.record_run(TestOutcome.FAILED, 50.0)
        metrics.record_run(TestOutcome.ERROR, 10.0)

        assert metrics.total_runs == 4
        assert metrics.outcomes["passed"] == 2
        assert metrics.outcomes["failed"] == 1
        assert metrics.outcomes["error"] == 1

    def test_actionable_rate(self):
        """Actionable rate should exclude unknown outcomes"""
        metrics = TestMetrics()

        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.FAILED, 100.0)
        metrics.record_run(TestOutcome.UNKNOWN, 100.0)

        # 2 actionable out of 3 = 66.67%
        assert abs(metrics.actionable_rate - 66.67) < 1

    def test_pass_rate(self):
        """Pass rate calculation"""
        metrics = TestMetrics()

        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.FAILED, 100.0)
        metrics.record_run(TestOutcome.FAILED, 100.0)

        assert metrics.pass_rate == 50.0

    def test_p95_duration(self):
        """95th percentile duration calculation"""
        metrics = TestMetrics()

        # Add 100 durations: 1, 2, 3, ..., 100
        for i in range(1, 101):
            metrics.record_run(TestOutcome.PASSED, float(i))

        # 95th percentile should be around 95
        assert metrics.p95_duration_ms >= 94
        assert metrics.p95_duration_ms <= 96

    def test_triage_time_tracking(self):
        """MTTT calculation"""
        metrics = TestMetrics()

        now = datetime.utcnow()
        from datetime import timedelta

        metrics.record_triage_time(now, now + timedelta(seconds=60))
        metrics.record_triage_time(now, now + timedelta(seconds=120))

        # Average should be 90 seconds
        assert metrics.mttt_seconds == 90.0

    def test_prometheus_format(self):
        """Prometheus exposition format export"""
        metrics = TestMetrics()
        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.FAILED, 50.0)

        prom_output = metrics.to_prometheus_format()

        assert "test_total 2" in prom_output
        assert 'test_outcomes_total{outcome="passed"} 1' in prom_output
        assert 'test_outcomes_total{outcome="failed"} 1' in prom_output
        assert "test_actionable_rate" in prom_output

    def test_to_dict(self):
        """Dictionary export"""
        metrics = TestMetrics()
        metrics.record_run(TestOutcome.PASSED, 100.0)

        result = metrics.to_dict()

        assert result["total_runs"] == 1
        assert result["outcomes"]["passed"] == 1
        assert "actionable_rate" in result
        assert "pass_rate" in result

    def test_correlation_id_recorded(self):
        """Correlation ID should be recorded with run"""
        metrics = TestMetrics()

        with correlation.context() as run_id:
            metrics.record_run(TestOutcome.PASSED, 100.0, test_name="test_correlated")

        assert len(metrics.recent_runs) == 1
        assert metrics.recent_runs[0].correlation_id == run_id

    def test_persistence_save_load(self, tmp_path):
        """Metrics should persist and load correctly"""
        metrics = TestMetrics()
        metrics._persistence_path = tmp_path / "test_metrics.json"

        metrics.record_run(TestOutcome.PASSED, 100.0)
        metrics.record_run(TestOutcome.FAILED, 50.0)

        # Save
        assert metrics.save() is True
        assert metrics._persistence_path.exists()

        # Create new instance and load
        metrics2 = TestMetrics()
        metrics2._persistence_path = tmp_path / "test_metrics.json"
        assert metrics2.load() is True

        assert metrics2.total_runs == 2
        assert metrics2.outcomes["passed"] == 1
        assert metrics2.outcomes["failed"] == 1


class TestParserMetrics:
    """Tests for parser metrics"""

    def test_record_success(self):
        """Recording successful parse"""
        metrics = ParserMetrics()

        metrics.record("genie", success=True, latency_ms=50.0, platform="cisco_xe")

        assert metrics.attempts["genie"] == 1
        assert metrics.successes["genie"] == 1
        assert metrics.failures["genie"] == 0

    def test_record_failure(self):
        """Recording failed parse"""
        metrics = ParserMetrics()

        metrics.record("ntc", success=False, latency_ms=10.0, error="No template")

        assert metrics.attempts["ntc"] == 1
        assert metrics.successes["ntc"] == 0
        assert metrics.failures["ntc"] == 1

    def test_multiple_parsers(self):
        """Tracking multiple parsers separately"""
        metrics = ParserMetrics()

        metrics.record("genie", True, 50.0)
        metrics.record("genie", True, 60.0)
        metrics.record("ntc", True, 30.0)
        metrics.record("ntc", False, 5.0)

        assert metrics.success_rate("genie") == 100.0
        assert metrics.success_rate("ntc") == 50.0

    def test_overall_success_rate(self):
        """Overall success rate across all parsers"""
        metrics = ParserMetrics()

        metrics.record("genie", True, 50.0)
        metrics.record("genie", True, 60.0)
        metrics.record("ntc", False, 5.0)
        metrics.record("ntc", False, 5.0)

        # 2 success out of 4 = 50%
        assert metrics.overall_success_rate == 50.0

    def test_avg_latency(self):
        """Average latency calculation"""
        metrics = ParserMetrics()

        metrics.record("genie", True, 50.0)
        metrics.record("genie", True, 100.0)
        metrics.record("genie", True, 150.0)

        assert metrics.avg_latency_ms("genie") == 100.0

    def test_prometheus_format(self):
        """Prometheus exposition format export"""
        metrics = ParserMetrics()
        metrics.record("genie", True, 50.0)
        metrics.record("ntc", False, 10.0)

        prom_output = metrics.to_prometheus_format()

        assert 'parser_attempts_total{parser="genie"} 1' in prom_output
        assert 'parser_successes_total{parser="genie"} 1' in prom_output
        assert "parser_overall_success_rate" in prom_output

    def test_to_dict(self):
        """Dictionary export with recent failures"""
        metrics = ParserMetrics()
        metrics.record("genie", True, 50.0)
        metrics.record("ntc", False, 10.0, error="No template found")

        result = metrics.to_dict()

        assert "overall_success_rate" in result
        assert "by_parser" in result
        assert "genie" in result["by_parser"]
        assert len(result["recent_failures"]) == 1

    def test_persistence_save_load(self, tmp_path):
        """Metrics should persist and load correctly"""
        metrics = ParserMetrics()
        metrics._persistence_path = tmp_path / "parser_metrics.json"

        metrics.record("genie", True, 50.0)
        metrics.record("ntc", False, 10.0)

        # Save
        assert metrics.save() is True

        # Create new instance and load
        metrics2 = ParserMetrics()
        metrics2._persistence_path = tmp_path / "parser_metrics.json"
        assert metrics2.load() is True

        assert metrics2.attempts["genie"] == 1
        assert metrics2.failures["ntc"] == 1


class TestThreadSafety:
    """Tests for thread safety of metrics"""

    def test_concurrent_recording(self):
        """Metrics should handle concurrent recording"""
        metrics = TestMetrics()
        threads = []

        def record_runs():
            for _ in range(100):
                metrics.record_run(TestOutcome.PASSED, 10.0)

        # Start 10 threads, each recording 100 runs
        for _ in range(10):
            t = threading.Thread(target=record_runs)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Should have exactly 1000 runs
        assert metrics.total_runs == 1000
        assert metrics.outcomes["passed"] == 1000
