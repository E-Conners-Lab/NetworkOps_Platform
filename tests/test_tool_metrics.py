"""Tests for core.tool_metrics — ToolMetrics class and track_tool_call decorator."""

import asyncio
import re
import tempfile
from pathlib import Path

import pytest

from core.tool_metrics import ToolMetrics, track_tool_call


# ---------------------------------------------------------------------------
# ToolMetrics.record
# ---------------------------------------------------------------------------

class TestToolMetricsRecord:
    def test_record_success(self):
        m = ToolMetrics()
        m.record("health_check", success=True, duration_ms=100.0)
        stats = m.get_stats("health_check")
        assert stats["calls"] == 1
        assert stats["successes"] == 1
        assert stats["failures"] == 0

    def test_record_failure(self):
        m = ToolMetrics()
        m.record("send_command", success=False, duration_ms=50.0)
        stats = m.get_stats("send_command")
        assert stats["calls"] == 1
        assert stats["successes"] == 0
        assert stats["failures"] == 1

    def test_duration_tracked(self):
        m = ToolMetrics()
        m.record("tool_a", success=True, duration_ms=200.0)
        m.record("tool_a", success=True, duration_ms=400.0)
        stats = m.get_stats("tool_a")
        assert stats["avg_ms"] == pytest.approx(300.0)
        assert stats["window_size"] == 2

    def test_ring_buffer_bounded(self):
        """Deque stays at maxlen=1000 even after 2000 recordings."""
        m = ToolMetrics()
        for i in range(2000):
            m.record("heavy", success=True, duration_ms=float(i))
        stats = m.get_stats("heavy")
        assert stats["window_size"] == 1000
        assert stats["calls"] == 2000  # Total counter still accurate

    def test_percentiles(self):
        m = ToolMetrics()
        for i in range(1, 101):
            m.record("pct", success=True, duration_ms=float(i))
        stats = m.get_stats("pct")
        assert stats["p50_ms"] == pytest.approx(50.0, abs=1)
        assert stats["p95_ms"] == pytest.approx(95.0, abs=1)

    def test_unknown_tool_returns_empty(self):
        m = ToolMetrics()
        assert m.get_stats("nonexistent") == {}


# ---------------------------------------------------------------------------
# Prometheus format
# ---------------------------------------------------------------------------

class TestPrometheusFormat:
    METRIC_NAME_RE = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*')

    def test_empty_metrics_returns_empty(self):
        m = ToolMetrics()
        assert m.to_prometheus_format() == ""

    def test_format_has_help_and_type(self):
        m = ToolMetrics()
        m.record("get_devices", success=True, duration_ms=10.0)
        output = m.to_prometheus_format()
        assert "# HELP mcp_tool_calls_total" in output
        assert "# TYPE mcp_tool_calls_total counter" in output
        assert "# HELP mcp_tool_duration_p95_ms" in output
        assert "# TYPE mcp_tool_duration_p95_ms gauge" in output

    def test_metric_names_valid(self):
        m = ToolMetrics()
        m.record("test_tool", success=True, duration_ms=5.0)
        output = m.to_prometheus_format()
        for line in output.splitlines():
            if line.startswith("#") or line == "":
                continue
            # Extract metric name (before { or space)
            name = line.split("{")[0].split(" ")[0]
            assert self.METRIC_NAME_RE.match(name), f"Invalid metric name: {name}"

    def test_tool_label_present(self):
        m = ToolMetrics()
        m.record("health_check", success=True, duration_ms=50.0)
        output = m.to_prometheus_format()
        assert 'tool="health_check"' in output


# ---------------------------------------------------------------------------
# Persistence round-trip
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "metrics.json"
            m1 = ToolMetrics(persistence_path=path)
            m1.record("tool_x", success=True, duration_ms=100.0)
            m1.record("tool_x", success=False, duration_ms=200.0)
            assert m1.save()

            m2 = ToolMetrics(persistence_path=path)
            assert m2.load()
            stats = m2.get_stats("tool_x")
            assert stats["calls"] == 2
            assert stats["successes"] == 1
            assert stats["failures"] == 1

    def test_saved_file_has_timestamp(self):
        import json
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "metrics.json"
            m = ToolMetrics(persistence_path=path)
            m.record("t", success=True, duration_ms=1.0)
            m.save()
            data = json.loads(path.read_text())
            assert "saved_at" in data

    def test_load_nonexistent_returns_false(self):
        m = ToolMetrics(persistence_path=Path("/tmp/nonexistent_metrics_12345.json"))
        assert m.load() is False


# ---------------------------------------------------------------------------
# track_tool_call decorator
# ---------------------------------------------------------------------------

class TestTrackToolCall:
    @pytest.mark.asyncio
    async def test_async_function(self):
        m = ToolMetrics()
        import core.tool_metrics
        original = core.tool_metrics.tool_metrics
        core.tool_metrics.tool_metrics = m

        try:
            async def my_tool(x: int) -> int:
                await asyncio.sleep(0.01)
                return x * 2

            tracked = track_tool_call("my_tool", my_tool)
            result = await tracked(5)
            assert result == 10
            stats = m.get_stats("my_tool")
            assert stats["calls"] == 1
            assert stats["successes"] == 1
            assert stats["avg_ms"] > 0
        finally:
            core.tool_metrics.tool_metrics = original

    def test_sync_function(self):
        m = ToolMetrics()
        import core.tool_metrics
        original = core.tool_metrics.tool_metrics
        core.tool_metrics.tool_metrics = m

        try:
            def add(a, b):
                return a + b

            tracked = track_tool_call("add", add)
            assert tracked(2, 3) == 5
            stats = m.get_stats("add")
            assert stats["calls"] == 1
            assert stats["successes"] == 1
        finally:
            core.tool_metrics.tool_metrics = original

    @pytest.mark.asyncio
    async def test_failure_recorded_on_exception(self):
        m = ToolMetrics()
        import core.tool_metrics
        original = core.tool_metrics.tool_metrics
        core.tool_metrics.tool_metrics = m

        try:
            async def failing_tool():
                raise ValueError("boom")

            tracked = track_tool_call("failing", failing_tool)
            with pytest.raises(ValueError):
                await tracked()

            stats = m.get_stats("failing")
            assert stats["calls"] == 1
            assert stats["failures"] == 1
            assert stats["successes"] == 0
        finally:
            core.tool_metrics.tool_metrics = original

    def test_preserves_function_name(self):
        async def original_name():
            pass

        tracked = track_tool_call("orig", original_name)
        assert tracked.__name__ == "original_name"
