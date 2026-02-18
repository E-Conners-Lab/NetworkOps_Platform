"""
Automation Metrics Collection and Persistence

Tracks test execution, parser success rates, and operational health.
Features:
- In-memory metrics with periodic disk persistence
- Prometheus exposition format export
- Correlation IDs for cross-tool tracing
- Historical baseline comparison

Usage:
    from core.metrics import test_metrics, parser_metrics, correlation

    # Record a test run
    with correlation.context() as run_id:
        test_metrics.record_run(TestOutcome.PASSED, duration_ms=150.5)
        parser_metrics.record("genie", success=True, latency_ms=45.2)

    # Get Prometheus format
    print(test_metrics.to_prometheus_format())

    # Persist to disk
    test_metrics.save()
"""

import json
import time
import uuid
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from core.timestamps import now, isonow
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Correlation ID Management
# =============================================================================

# Context variable for request/run correlation
_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


class CorrelationContext:
    """
    Manages correlation IDs for cross-tool tracing.

    Usage:
        with correlation.context() as run_id:
            # All operations in this block share the same run_id
            logger.info("Starting test", extra={"run_id": run_id})
            test_metrics.record_run(...)

        # Or set explicitly
        correlation.set("my-custom-id")
        run_id = correlation.get()
    """

    def __init__(self):
        self._lock = threading.Lock()

    def get(self) -> Optional[str]:
        """Get current correlation ID"""
        return _correlation_id.get()

    def set(self, correlation_id: str) -> None:
        """Set correlation ID for current context"""
        _correlation_id.set(correlation_id)

    def generate(self) -> str:
        """Generate a new correlation ID"""
        return f"run-{now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

    def context(self):
        """Context manager that sets a new correlation ID"""
        return _CorrelationContextManager(self)

    def clear(self) -> None:
        """Clear the current correlation ID"""
        _correlation_id.set(None)


class _CorrelationContextManager:
    """Context manager for correlation ID scope"""

    def __init__(self, correlation: CorrelationContext):
        self._correlation = correlation
        self._token = None
        self._run_id = None

    def __enter__(self) -> str:
        self._run_id = self._correlation.generate()
        self._token = _correlation_id.set(self._run_id)
        return self._run_id

    def __exit__(self, *args):
        _correlation_id.set(None)


# Singleton instance
correlation = CorrelationContext()


# =============================================================================
# Test Metrics
# =============================================================================

class TestOutcome(Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass
class TestRun:
    """Individual test run record"""
    timestamp: str
    outcome: str
    duration_ms: float
    correlation_id: Optional[str] = None
    test_name: Optional[str] = None
    device: Optional[str] = None


@dataclass
class TestMetrics:
    """Track test execution metrics for observability"""

    total_runs: int = 0
    outcomes: Dict[str, int] = field(default_factory=lambda: {
        "passed": 0, "failed": 0, "error": 0, "skipped": 0, "unknown": 0
    })
    durations_ms: List[float] = field(default_factory=list)
    detection_to_triage_times: List[float] = field(default_factory=list)
    recent_runs: List[TestRun] = field(default_factory=list)
    _max_recent: int = 1000
    _persistence_path: Optional[Path] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        if self._persistence_path is None:
            self._persistence_path = Path(__file__).parent.parent / "data" / "metrics" / "test_metrics.json"

    def record_run(
        self,
        outcome: TestOutcome,
        duration_ms: float,
        test_name: Optional[str] = None,
        device: Optional[str] = None
    ):
        """Record a test execution"""
        with self._lock:
            self.total_runs += 1
            self.outcomes[outcome.value] += 1
            self.durations_ms.append(duration_ms)

            # Keep only recent durations for percentile calculations
            if len(self.durations_ms) > 10000:
                self.durations_ms = self.durations_ms[-5000:]

            # Record run details
            run = TestRun(
                timestamp=isonow(),
                outcome=outcome.value,
                duration_ms=duration_ms,
                correlation_id=correlation.get(),
                test_name=test_name,
                device=device
            )
            self.recent_runs.append(run)

            # Trim old runs
            if len(self.recent_runs) > self._max_recent:
                self.recent_runs = self.recent_runs[-self._max_recent:]

    def record_triage_time(self, detection_time: datetime, triage_time: datetime):
        """Track time from detection to triage (MTTT)"""
        with self._lock:
            delta = (triage_time - detection_time).total_seconds()
            self.detection_to_triage_times.append(delta)

            if len(self.detection_to_triage_times) > 1000:
                self.detection_to_triage_times = self.detection_to_triage_times[-500:]

    @property
    def actionable_rate(self) -> float:
        """Percentage of tests with actionable (non-unknown) outcomes"""
        if self.total_runs == 0:
            return 0.0
        unknown = self.outcomes.get("unknown", 0)
        return ((self.total_runs - unknown) / self.total_runs) * 100

    @property
    def pass_rate(self) -> float:
        """Percentage of tests that passed"""
        if self.total_runs == 0:
            return 0.0
        passed = self.outcomes.get("passed", 0)
        return (passed / self.total_runs) * 100

    @property
    def mttt_seconds(self) -> Optional[float]:
        """Mean Time To Triage"""
        if not self.detection_to_triage_times:
            return None
        return sum(self.detection_to_triage_times) / len(self.detection_to_triage_times)

    @property
    def p95_duration_ms(self) -> Optional[float]:
        """95th percentile test duration"""
        if not self.durations_ms:
            return None
        sorted_durations = sorted(self.durations_ms)
        idx = int(len(sorted_durations) * 0.95)
        return sorted_durations[min(idx, len(sorted_durations) - 1)]

    @property
    def p50_duration_ms(self) -> Optional[float]:
        """Median test duration"""
        if not self.durations_ms:
            return None
        sorted_durations = sorted(self.durations_ms)
        idx = len(sorted_durations) // 2
        return sorted_durations[idx]

    def to_prometheus_format(self) -> str:
        """Export metrics in Prometheus exposition format"""
        lines = [
            "# HELP test_total Total test executions",
            "# TYPE test_total counter",
            f"test_total {self.total_runs}",
            "",
            "# HELP test_outcomes_total Test outcomes by type",
            "# TYPE test_outcomes_total counter",
        ]
        for outcome, count in self.outcomes.items():
            lines.append(f'test_outcomes_total{{outcome="{outcome}"}} {count}')

        lines.extend([
            "",
            "# HELP test_actionable_rate Percentage of actionable test results",
            "# TYPE test_actionable_rate gauge",
            f"test_actionable_rate {self.actionable_rate:.2f}",
            "",
            "# HELP test_pass_rate Percentage of tests passed",
            "# TYPE test_pass_rate gauge",
            f"test_pass_rate {self.pass_rate:.2f}",
        ])

        if self.mttt_seconds is not None:
            lines.extend([
                "",
                "# HELP mttt_seconds Mean Time To Triage",
                "# TYPE mttt_seconds gauge",
                f"mttt_seconds {self.mttt_seconds:.2f}",
            ])

        if self.p95_duration_ms is not None:
            lines.extend([
                "",
                "# HELP test_duration_p95_ms 95th percentile test duration",
                "# TYPE test_duration_p95_ms gauge",
                f"test_duration_p95_ms {self.p95_duration_ms:.2f}",
            ])

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary"""
        return {
            "total_runs": self.total_runs,
            "outcomes": self.outcomes,
            "actionable_rate": round(self.actionable_rate, 2),
            "pass_rate": round(self.pass_rate, 2),
            "mttt_seconds": self.mttt_seconds,
            "p50_duration_ms": self.p50_duration_ms,
            "p95_duration_ms": self.p95_duration_ms,
            "recent_runs_count": len(self.recent_runs),
        }

    def save(self) -> bool:
        """Persist metrics to disk"""
        try:
            self._persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "saved_at": isonow(),
                "total_runs": self.total_runs,
                "outcomes": self.outcomes,
                "recent_runs": [asdict(r) for r in self.recent_runs[-100:]],
                "durations_sample": self.durations_ms[-1000:],
                "triage_times_sample": self.detection_to_triage_times[-100:],
            }

            with open(self._persistence_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Saved test metrics to {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save test metrics: {e}")
            return False

    def load(self) -> bool:
        """Load metrics from disk"""
        try:
            if not self._persistence_path.exists():
                return False

            with open(self._persistence_path) as f:
                data = json.load(f)

            with self._lock:
                self.total_runs = data.get("total_runs", 0)
                self.outcomes = data.get("outcomes", self.outcomes)
                self.durations_ms = data.get("durations_sample", [])
                self.detection_to_triage_times = data.get("triage_times_sample", [])

                # Restore recent runs
                for run_data in data.get("recent_runs", []):
                    self.recent_runs.append(TestRun(**run_data))

            logger.info(f"Loaded test metrics from {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load test metrics: {e}")
            return False


# =============================================================================
# Parser Metrics
# =============================================================================

@dataclass
class ParserAttempt:
    """Individual parser attempt record"""
    timestamp: str
    parser: str
    success: bool
    latency_ms: float
    platform: Optional[str] = None
    command: Optional[str] = None
    correlation_id: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ParserMetrics:
    """Track parser success/failure for observability"""

    attempts: Dict[str, int] = field(default_factory=dict)
    successes: Dict[str, int] = field(default_factory=dict)
    failures: Dict[str, int] = field(default_factory=dict)
    latencies_ms: Dict[str, List[float]] = field(default_factory=dict)
    recent_attempts: List[ParserAttempt] = field(default_factory=list)
    _max_recent: int = 500
    _persistence_path: Optional[Path] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        if self._persistence_path is None:
            self._persistence_path = Path(__file__).parent.parent / "data" / "metrics" / "parser_metrics.json"

    def record(
        self,
        parser: str,
        success: bool,
        latency_ms: float,
        platform: Optional[str] = None,
        command: Optional[str] = None,
        error: Optional[str] = None
    ):
        """Record a parser attempt"""
        with self._lock:
            if parser not in self.attempts:
                self.attempts[parser] = 0
                self.successes[parser] = 0
                self.failures[parser] = 0
                self.latencies_ms[parser] = []

            self.attempts[parser] += 1
            if success:
                self.successes[parser] += 1
            else:
                self.failures[parser] += 1

            self.latencies_ms[parser].append(latency_ms)
            if len(self.latencies_ms[parser]) > 1000:
                self.latencies_ms[parser] = self.latencies_ms[parser][-500:]

            # Record attempt details
            attempt = ParserAttempt(
                timestamp=isonow(),
                parser=parser,
                success=success,
                latency_ms=latency_ms,
                platform=platform,
                command=command,
                correlation_id=correlation.get(),
                error=error
            )
            self.recent_attempts.append(attempt)

            if len(self.recent_attempts) > self._max_recent:
                self.recent_attempts = self.recent_attempts[-self._max_recent:]

    def success_rate(self, parser: str) -> float:
        """Get success rate for a specific parser"""
        if self.attempts.get(parser, 0) == 0:
            return 0.0
        return (self.successes[parser] / self.attempts[parser]) * 100

    def avg_latency_ms(self, parser: str) -> Optional[float]:
        """Get average latency for a specific parser"""
        latencies = self.latencies_ms.get(parser, [])
        if not latencies:
            return None
        return sum(latencies) / len(latencies)

    @property
    def overall_success_rate(self) -> float:
        """Overall success rate across all parsers"""
        total_attempts = sum(self.attempts.values())
        total_successes = sum(self.successes.values())
        if total_attempts == 0:
            return 0.0
        return (total_successes / total_attempts) * 100

    def to_prometheus_format(self) -> str:
        """Export metrics in Prometheus exposition format"""
        lines = [
            "# HELP parser_attempts_total Total parser attempts",
            "# TYPE parser_attempts_total counter",
        ]
        for parser, count in self.attempts.items():
            lines.append(f'parser_attempts_total{{parser="{parser}"}} {count}')

        lines.extend([
            "",
            "# HELP parser_successes_total Successful parser attempts",
            "# TYPE parser_successes_total counter",
        ])
        for parser, count in self.successes.items():
            lines.append(f'parser_successes_total{{parser="{parser}"}} {count}')

        lines.extend([
            "",
            "# HELP parser_success_rate Parser success rate percentage",
            "# TYPE parser_success_rate gauge",
        ])
        for parser in self.attempts.keys():
            rate = self.success_rate(parser)
            lines.append(f'parser_success_rate{{parser="{parser}"}} {rate:.2f}')

        lines.extend([
            "",
            "# HELP parser_overall_success_rate Overall parser success rate",
            "# TYPE parser_overall_success_rate gauge",
            f"parser_overall_success_rate {self.overall_success_rate:.2f}",
        ])

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export metrics as dictionary"""
        return {
            "overall_success_rate": round(self.overall_success_rate, 2),
            "by_parser": {
                parser: {
                    "attempts": self.attempts.get(parser, 0),
                    "successes": self.successes.get(parser, 0),
                    "failures": self.failures.get(parser, 0),
                    "success_rate": round(self.success_rate(parser), 2),
                    "avg_latency_ms": round(self.avg_latency_ms(parser) or 0, 2),
                }
                for parser in self.attempts.keys()
            },
            "recent_failures": [
                asdict(a) for a in self.recent_attempts
                if not a.success
            ][-10:]
        }

    def save(self) -> bool:
        """Persist metrics to disk"""
        try:
            self._persistence_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "saved_at": isonow(),
                "attempts": self.attempts,
                "successes": self.successes,
                "failures": self.failures,
                "recent_attempts": [asdict(a) for a in self.recent_attempts[-100:]],
            }

            with open(self._persistence_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Saved parser metrics to {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save parser metrics: {e}")
            return False

    def load(self) -> bool:
        """Load metrics from disk"""
        try:
            if not self._persistence_path.exists():
                return False

            with open(self._persistence_path) as f:
                data = json.load(f)

            with self._lock:
                self.attempts = data.get("attempts", {})
                self.successes = data.get("successes", {})
                self.failures = data.get("failures", {})

                for attempt_data in data.get("recent_attempts", []):
                    self.recent_attempts.append(ParserAttempt(**attempt_data))

            logger.info(f"Loaded parser metrics from {self._persistence_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load parser metrics: {e}")
            return False


# =============================================================================
# Global Instances
# =============================================================================

test_metrics = TestMetrics()
parser_metrics = ParserMetrics()


def save_all_metrics() -> bool:
    """Save all metrics to disk"""
    return test_metrics.save() and parser_metrics.save()


def load_all_metrics() -> bool:
    """Load all metrics from disk"""
    return test_metrics.load() and parser_metrics.load()
