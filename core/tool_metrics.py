"""
MCP Tool Metrics Collection

Tracks per-tool call counts, success/failure rates, and latency percentiles.
Uses a fixed-size deque for duration samples (constant memory) and running
counters for accurate totals.

Usage:
    from core.tool_metrics import tool_metrics, track_tool_call

    # Decorator usage (wraps async or sync functions)
    tracked_fn = track_tool_call("health_check", original_fn)

    # Manual recording
    tool_metrics.record("health_check", success=True, duration_ms=142.5)

    # Prometheus format
    print(tool_metrics.to_prometheus_format())
"""

import asyncio
import functools
import json
import logging
import threading
import time
from collections import deque
from core.timestamps import isonow
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

DURATION_WINDOW = 1000  # Fixed-size window for percentile calculations


class ToolMetrics:
    """Per-tool observability: counts, durations, percentiles."""

    def __init__(self, persistence_path: Optional[Path] = None):
        self._persistence_path = persistence_path or (
            Path(__file__).parent.parent / "data" / "metrics" / "tool_metrics.json"
        )
        # Per-tool counters
        self._calls: Dict[str, int] = {}
        self._successes: Dict[str, int] = {}
        self._failures: Dict[str, int] = {}

        # Per-tool duration tracking
        self._durations: Dict[str, deque] = {}  # deque(maxlen=DURATION_WINDOW)
        self._duration_sum: Dict[str, float] = {}
        self._duration_count: Dict[str, int] = {}

        # Thread safety for sync callers
        self._sync_lock = threading.Lock()
        # Async lock created lazily to avoid event loop issues at import time
        self._async_lock: Optional[asyncio.Lock] = None

    def _get_async_lock(self) -> asyncio.Lock:
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _ensure_tool(self, tool_name: str) -> None:
        """Initialize counters for a tool if not yet seen."""
        if tool_name not in self._calls:
            self._calls[tool_name] = 0
            self._successes[tool_name] = 0
            self._failures[tool_name] = 0
            self._durations[tool_name] = deque(maxlen=DURATION_WINDOW)
            self._duration_sum[tool_name] = 0.0
            self._duration_count[tool_name] = 0

    def record(self, tool_name: str, success: bool, duration_ms: float) -> None:
        """Record a tool call result (thread-safe)."""
        with self._sync_lock:
            self._ensure_tool(tool_name)
            self._calls[tool_name] += 1
            if success:
                self._successes[tool_name] += 1
            else:
                self._failures[tool_name] += 1
            self._durations[tool_name].append(duration_ms)
            self._duration_sum[tool_name] += duration_ms
            self._duration_count[tool_name] += 1

    def get_tools(self) -> list[str]:
        """Return list of tracked tool names."""
        return list(self._calls.keys())

    def get_stats(self, tool_name: str) -> Dict[str, Any]:
        """Get stats for a single tool."""
        if tool_name not in self._calls:
            return {}
        durations = sorted(self._durations[tool_name])
        count = self._duration_count[tool_name]
        return {
            "calls": self._calls[tool_name],
            "successes": self._successes[tool_name],
            "failures": self._failures[tool_name],
            "avg_ms": (self._duration_sum[tool_name] / count) if count > 0 else 0,
            "p50_ms": self._percentile(durations, 0.50),
            "p95_ms": self._percentile(durations, 0.95),
            "window_size": len(durations),
        }

    @staticmethod
    def _percentile(sorted_values: list, pct: float) -> Optional[float]:
        if not sorted_values:
            return None
        idx = int(len(sorted_values) * pct)
        return sorted_values[min(idx, len(sorted_values) - 1)]

    def to_prometheus_format(self) -> str:
        """Export all tool metrics in Prometheus exposition format."""
        if not self._calls:
            return ""

        lines = [
            "# HELP mcp_tool_calls_total Total MCP tool calls",
            "# TYPE mcp_tool_calls_total counter",
        ]
        for tool, count in self._calls.items():
            lines.append(f'mcp_tool_calls_total{{tool="{tool}"}} {count}')

        lines.extend([
            "",
            "# HELP mcp_tool_successes_total Successful MCP tool calls",
            "# TYPE mcp_tool_successes_total counter",
        ])
        for tool, count in self._successes.items():
            lines.append(f'mcp_tool_successes_total{{tool="{tool}"}} {count}')

        lines.extend([
            "",
            "# HELP mcp_tool_failures_total Failed MCP tool calls",
            "# TYPE mcp_tool_failures_total counter",
        ])
        for tool, count in self._failures.items():
            lines.append(f'mcp_tool_failures_total{{tool="{tool}"}} {count}')

        lines.extend([
            "",
            "# HELP mcp_tool_duration_avg_ms Average tool call duration (ms)",
            "# TYPE mcp_tool_duration_avg_ms gauge",
        ])
        for tool in self._calls:
            count = self._duration_count[tool]
            if count > 0:
                avg = self._duration_sum[tool] / count
                lines.append(f'mcp_tool_duration_avg_ms{{tool="{tool}"}} {avg:.2f}')

        lines.extend([
            "",
            "# HELP mcp_tool_duration_p95_ms 95th percentile tool call duration (ms)",
            "# TYPE mcp_tool_duration_p95_ms gauge",
        ])
        for tool in self._calls:
            durations = sorted(self._durations[tool])
            p95 = self._percentile(durations, 0.95)
            if p95 is not None:
                lines.append(f'mcp_tool_duration_p95_ms{{tool="{tool}"}} {p95:.2f}')

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary."""
        return {
            tool: self.get_stats(tool)
            for tool in self._calls
        }

    def save(self) -> bool:
        """Persist metrics to disk."""
        try:
            self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "saved_at": isonow(),
                "tools": {},
            }
            for tool in self._calls:
                data["tools"][tool] = {
                    "calls": self._calls[tool],
                    "successes": self._successes[tool],
                    "failures": self._failures[tool],
                    "duration_sum": self._duration_sum[tool],
                    "duration_count": self._duration_count[tool],
                    "durations_sample": list(self._durations[tool]),
                }
            with open(self._persistence_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved tool metrics to {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save tool metrics: {e}")
            return False

    def load(self) -> bool:
        """Load metrics from disk."""
        try:
            if not self._persistence_path.exists():
                return False
            with open(self._persistence_path) as f:
                data = json.load(f)
            with self._sync_lock:
                for tool, stats in data.get("tools", {}).items():
                    self._ensure_tool(tool)
                    self._calls[tool] = stats.get("calls", 0)
                    self._successes[tool] = stats.get("successes", 0)
                    self._failures[tool] = stats.get("failures", 0)
                    self._duration_sum[tool] = stats.get("duration_sum", 0.0)
                    self._duration_count[tool] = stats.get("duration_count", 0)
                    for d in stats.get("durations_sample", []):
                        self._durations[tool].append(d)
            logger.info(f"Loaded tool metrics from {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load tool metrics: {e}")
            return False


# Singleton instance
tool_metrics = ToolMetrics()


def track_tool_call(tool_name: str, fn: Callable) -> Callable:
    """Wrap an async or sync tool function with timing and metrics recording."""
    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            start = time.monotonic()
            success = True
            try:
                return await fn(*args, **kwargs)
            except Exception:
                success = False
                raise
            finally:
                duration_ms = (time.monotonic() - start) * 1000
                tool_metrics.record(tool_name, success, duration_ms)
        return async_wrapper
    else:
        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            start = time.monotonic()
            success = True
            try:
                return fn(*args, **kwargs)
            except Exception:
                success = False
                raise
            finally:
                duration_ms = (time.monotonic() - start) * 1000
                tool_metrics.record(tool_name, success, duration_ms)
        return sync_wrapper
