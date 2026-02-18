"""
Network Traffic Baselining for NetworkOps.

Establishes normal traffic patterns and detects anomalies when traffic
deviates significantly from the baseline.

Features:
- Interface traffic collection via SNMP/CLI
- Statistical baseline calculation (mean, std dev, percentiles)
- Anomaly detection using z-score and IQR methods
- Utilization tracking and trending
- Historical data storage in SQLite

Usage:
    from core.traffic_baseline import TrafficBaseline

    baseline = TrafficBaseline()

    # Collect current metrics
    await baseline.collect_metrics("R1")

    # Build baseline from collected data
    baseline.calculate_baseline("R1", "GigabitEthernet1", days=7)

    # Check for anomalies
    anomalies = await baseline.detect_anomalies("R1")
"""

import asyncio
import json
import logging
import math
import sqlite3
import statistics
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from core.timestamps import now, isonow
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

BASELINE_DB = Path(__file__).parent.parent / "data" / "traffic_baseline.db"

# Import UnifiedDB for centralized database access
from core.unified_db import UnifiedDB

# Anomaly detection thresholds
ZSCORE_THRESHOLD = 3.0  # Standard deviations from mean
IQR_MULTIPLIER = 1.5  # IQR multiplier for outlier detection
MIN_SAMPLES_FOR_BASELINE = 10  # Minimum samples to build baseline


# =============================================================================
# Data Models
# =============================================================================

class AnomalyType(str, Enum):
    HIGH_UTILIZATION = "high_utilization"
    LOW_UTILIZATION = "low_utilization"
    HIGH_ERRORS = "high_errors"
    TRAFFIC_SPIKE = "traffic_spike"
    TRAFFIC_DROP = "traffic_drop"
    INTERFACE_DOWN = "interface_down"


class MetricType(str, Enum):
    IN_OCTETS = "in_octets"
    OUT_OCTETS = "out_octets"
    IN_PACKETS = "in_packets"
    OUT_PACKETS = "out_packets"
    IN_ERRORS = "in_errors"
    OUT_ERRORS = "out_errors"
    IN_DISCARDS = "in_discards"
    OUT_DISCARDS = "out_discards"


@dataclass
class InterfaceMetrics:
    """Traffic metrics for a single interface."""
    device: str
    interface: str
    timestamp: str
    in_octets: int = 0
    out_octets: int = 0
    in_packets: int = 0
    out_packets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    speed: int = 0  # Interface speed in bps
    admin_status: str = "up"
    oper_status: str = "up"

    # Calculated rates (per second)
    in_bps: float = 0.0
    out_bps: float = 0.0
    in_pps: float = 0.0
    out_pps: float = 0.0
    in_utilization: float = 0.0  # Percentage
    out_utilization: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BaselineStats:
    """Statistical baseline for an interface metric."""
    device: str
    interface: str
    metric: str
    samples: int
    mean: float
    std_dev: float
    min_val: float
    max_val: float
    p25: float  # 25th percentile
    p50: float  # Median
    p75: float  # 75th percentile
    p95: float  # 95th percentile
    calculated_at: str
    period_days: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TrafficAnomaly:
    """Detected traffic anomaly."""
    device: str
    interface: str
    anomaly_type: AnomalyType
    metric: str
    current_value: float
    baseline_mean: float
    baseline_std: float
    zscore: float
    severity: str  # low, medium, high, critical
    detected_at: str
    message: str

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "anomaly_type": self.anomaly_type.value,
        }


# =============================================================================
# Traffic Baseline Engine
# =============================================================================

class TrafficBaseline:
    """
    Network traffic baselining and anomaly detection.
    """

    def __init__(self, db_path: Path = None, db: UnifiedDB = None):
        self.db = db or UnifiedDB.get_instance()
        self.db_path = db_path or self.db.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if db_path and not db:
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Get a database connection (unified or standalone)."""
        if self.db:
            return self.db.connect()
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize SQLite database for traffic data (standalone mode)."""
        with self._connect() as conn:
            # Raw metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    in_octets INTEGER,
                    out_octets INTEGER,
                    in_packets INTEGER,
                    out_packets INTEGER,
                    in_errors INTEGER,
                    out_errors INTEGER,
                    in_discards INTEGER,
                    out_discards INTEGER,
                    speed INTEGER,
                    admin_status TEXT,
                    oper_status TEXT,
                    in_bps REAL,
                    out_bps REAL,
                    in_utilization REAL,
                    out_utilization REAL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_device_intf
                ON traffic_metrics(device, interface, timestamp)
            """)

            # Baseline statistics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    samples INTEGER,
                    mean REAL,
                    std_dev REAL,
                    min_val REAL,
                    max_val REAL,
                    p25 REAL,
                    p50 REAL,
                    p75 REAL,
                    p95 REAL,
                    calculated_at TEXT,
                    period_days INTEGER,
                    UNIQUE(device, interface, metric)
                )
            """)

            # Anomalies table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    metric TEXT,
                    current_value REAL,
                    baseline_mean REAL,
                    baseline_std REAL,
                    zscore REAL,
                    severity TEXT,
                    detected_at TEXT,
                    message TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_device
                ON anomalies(device, detected_at)
            """)

            conn.commit()

    async def collect_metrics(
        self,
        device_name: str,
        interfaces: list[str] = None,
    ) -> list[InterfaceMetrics]:
        """
        Collect current traffic metrics from a device.

        Args:
            device_name: Device to collect from
            interfaces: Specific interfaces (all if None)

        Returns:
            List of InterfaceMetrics
        """
        from config.devices import DEVICES
        from core.scrapli_manager import get_ios_xe_connection

        if device_name not in DEVICES:
            raise ValueError(f"Device '{device_name}' not found")

        metrics = []
        timestamp = isonow()

        try:
            async with get_ios_xe_connection(device_name) as conn:
                # Get interface statistics
                resp = await conn.send_command("show interfaces")
                parsed = self._parse_interface_stats(resp.result, device_name, timestamp)

                # Filter if specific interfaces requested
                if interfaces:
                    parsed = [m for m in parsed if m.interface in interfaces]

                # Get previous metrics for rate calculation
                for metric in parsed:
                    prev = self._get_previous_metric(device_name, metric.interface)
                    if prev:
                        metric = self._calculate_rates(metric, prev)

                    metrics.append(metric)
                    self._save_metric(metric)

        except Exception as e:
            logger.error(f"Failed to collect metrics from {device_name}: {e}")
            raise

        return metrics

    def _parse_interface_stats(
        self,
        output: str,
        device: str,
        timestamp: str,
    ) -> list[InterfaceMetrics]:
        """Parse 'show interfaces' output."""
        import re

        metrics = []
        current_intf = None
        current_metrics = {}

        for line in output.split("\n"):
            # Interface line: "GigabitEthernet1 is up, line protocol is up"
            intf_match = re.match(r"^(\S+) is (\w+), line protocol is (\w+)", line)
            if intf_match:
                # Save previous interface
                if current_intf and current_metrics:
                    metrics.append(InterfaceMetrics(
                        device=device,
                        interface=current_intf,
                        timestamp=timestamp,
                        **current_metrics,
                    ))

                current_intf = intf_match.group(1)
                current_metrics = {
                    "admin_status": intf_match.group(2),
                    "oper_status": intf_match.group(3),
                }
                continue

            if not current_intf:
                continue

            # Speed: "BW 1000000 Kbit/sec"
            speed_match = re.search(r"BW (\d+) Kbit", line)
            if speed_match:
                current_metrics["speed"] = int(speed_match.group(1)) * 1000  # Convert to bps

            # Input packets/bytes
            in_match = re.search(r"(\d+) packets input, (\d+) bytes", line)
            if in_match:
                current_metrics["in_packets"] = int(in_match.group(1))
                current_metrics["in_octets"] = int(in_match.group(2))

            # Output packets/bytes
            out_match = re.search(r"(\d+) packets output, (\d+) bytes", line)
            if out_match:
                current_metrics["out_packets"] = int(out_match.group(1))
                current_metrics["out_octets"] = int(out_match.group(2))

            # Input errors
            in_err_match = re.search(r"(\d+) input errors", line)
            if in_err_match:
                current_metrics["in_errors"] = int(in_err_match.group(1))

            # Output errors
            out_err_match = re.search(r"(\d+) output errors", line)
            if out_err_match:
                current_metrics["out_errors"] = int(out_err_match.group(1))

        # Don't forget the last interface
        if current_intf and current_metrics:
            metrics.append(InterfaceMetrics(
                device=device,
                interface=current_intf,
                timestamp=timestamp,
                **current_metrics,
            ))

        return metrics

    def _calculate_rates(
        self,
        current: InterfaceMetrics,
        previous: InterfaceMetrics,
    ) -> InterfaceMetrics:
        """Calculate rates between two samples."""
        try:
            # Calculate time delta
            curr_time = datetime.fromisoformat(current.timestamp)
            prev_time = datetime.fromisoformat(previous.timestamp)
            delta_seconds = (curr_time - prev_time).total_seconds()

            if delta_seconds <= 0:
                return current

            # Handle counter wraps (32-bit counters)
            max_counter = 2**32

            def calc_delta(curr, prev):
                if curr >= prev:
                    return curr - prev
                else:
                    return (max_counter - prev) + curr

            # Calculate byte rates
            in_delta = calc_delta(current.in_octets, previous.in_octets)
            out_delta = calc_delta(current.out_octets, previous.out_octets)

            current.in_bps = (in_delta * 8) / delta_seconds
            current.out_bps = (out_delta * 8) / delta_seconds

            # Calculate packet rates
            in_pkt_delta = calc_delta(current.in_packets, previous.in_packets)
            out_pkt_delta = calc_delta(current.out_packets, previous.out_packets)

            current.in_pps = in_pkt_delta / delta_seconds
            current.out_pps = out_pkt_delta / delta_seconds

            # Calculate utilization
            if current.speed > 0:
                current.in_utilization = (current.in_bps / current.speed) * 100
                current.out_utilization = (current.out_bps / current.speed) * 100

        except Exception as e:
            logger.warning(f"Rate calculation error: {e}")

        return current

    def _get_previous_metric(
        self,
        device: str,
        interface: str,
    ) -> Optional[InterfaceMetrics]:
        """Get the most recent metric for rate calculation."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM traffic_metrics
                WHERE device = ? AND interface = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (device, interface)).fetchone()

            if not row:
                return None

            return InterfaceMetrics(
                device=row["device"],
                interface=row["interface"],
                timestamp=row["timestamp"],
                in_octets=row["in_octets"] or 0,
                out_octets=row["out_octets"] or 0,
                in_packets=row["in_packets"] or 0,
                out_packets=row["out_packets"] or 0,
                in_errors=row["in_errors"] or 0,
                out_errors=row["out_errors"] or 0,
                speed=row["speed"] or 0,
            )

    def _save_metric(self, metric: InterfaceMetrics):
        """Save metric to database."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO traffic_metrics
                (device, interface, timestamp, in_octets, out_octets,
                 in_packets, out_packets, in_errors, out_errors,
                 in_discards, out_discards, speed, admin_status, oper_status,
                 in_bps, out_bps, in_utilization, out_utilization)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.device, metric.interface, metric.timestamp,
                metric.in_octets, metric.out_octets,
                metric.in_packets, metric.out_packets,
                metric.in_errors, metric.out_errors,
                metric.in_discards, metric.out_discards,
                metric.speed, metric.admin_status, metric.oper_status,
                metric.in_bps, metric.out_bps,
                metric.in_utilization, metric.out_utilization,
            ))
            conn.commit()

    def calculate_baseline(
        self,
        device: str,
        interface: str,
        days: int = 7,
        metrics: list[str] = None,
    ) -> list[BaselineStats]:
        """
        Calculate baseline statistics from historical data.

        Args:
            device: Device name
            interface: Interface name
            days: Number of days of data to use
            metrics: Specific metrics (default: utilization, errors)

        Returns:
            List of BaselineStats for each metric
        """
        if metrics is None:
            metrics = ["in_utilization", "out_utilization", "in_errors", "out_errors"]

        cutoff = (now() - timedelta(days=days)).isoformat()
        baselines = []

        with self._connect() as conn:
            for metric_name in metrics:
                # Get historical values
                query = f"SELECT {metric_name} FROM traffic_metrics WHERE device = ? AND interface = ? AND timestamp >= ? AND {metric_name} IS NOT NULL ORDER BY timestamp"  # nosec B608
                rows = conn.execute(query, (device, interface, cutoff)).fetchall()

                values = [r[0] for r in rows if r[0] is not None]

                if len(values) < MIN_SAMPLES_FOR_BASELINE:
                    logger.warning(
                        f"Insufficient samples for {device}/{interface}/{metric_name}: "
                        f"{len(values)} < {MIN_SAMPLES_FOR_BASELINE}"
                    )
                    continue

                # Calculate statistics
                baseline = BaselineStats(
                    device=device,
                    interface=interface,
                    metric=metric_name,
                    samples=len(values),
                    mean=statistics.mean(values),
                    std_dev=statistics.stdev(values) if len(values) > 1 else 0,
                    min_val=min(values),
                    max_val=max(values),
                    p25=self._percentile(values, 25),
                    p50=statistics.median(values),
                    p75=self._percentile(values, 75),
                    p95=self._percentile(values, 95),
                    calculated_at=isonow(),
                    period_days=days,
                )

                # Save baseline
                self._save_baseline(baseline)
                baselines.append(baseline)

        return baselines

    def _percentile(self, values: list[float], p: int) -> float:
        """Calculate percentile."""
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * p / 100
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return sorted_vals[int(k)]

        return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)

    def _save_baseline(self, baseline: BaselineStats):
        """Save or update baseline in database."""
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO traffic_baselines
                (device, interface, metric, samples, mean, std_dev,
                 min_val, max_val, p25, p50, p75, p95, calculated_at, period_days)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                baseline.device, baseline.interface, baseline.metric,
                baseline.samples, baseline.mean, baseline.std_dev,
                baseline.min_val, baseline.max_val,
                baseline.p25, baseline.p50, baseline.p75, baseline.p95,
                baseline.calculated_at, baseline.period_days,
            ))
            conn.commit()

    def get_baseline(self, device: str, interface: str, metric: str) -> Optional[BaselineStats]:
        """Get baseline for a specific metric."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM traffic_baselines
                WHERE device = ? AND interface = ? AND metric = ?
            """, (device, interface, metric)).fetchone()

            if not row:
                return None

            return BaselineStats(**dict(row))

    async def detect_anomalies(
        self,
        device_name: str,
        interfaces: list[str] = None,
    ) -> list[TrafficAnomaly]:
        """
        Detect traffic anomalies against baselines.

        Args:
            device_name: Device to check
            interfaces: Specific interfaces (all if None)

        Returns:
            List of detected anomalies
        """
        # Collect current metrics
        current_metrics = await self.collect_metrics(device_name, interfaces)
        anomalies = []

        for metric in current_metrics:
            # Check interface down
            if metric.oper_status.lower() != "up":
                anomalies.append(TrafficAnomaly(
                    device=device_name,
                    interface=metric.interface,
                    anomaly_type=AnomalyType.INTERFACE_DOWN,
                    metric="oper_status",
                    current_value=0,
                    baseline_mean=0,
                    baseline_std=0,
                    zscore=0,
                    severity="critical",
                    detected_at=metric.timestamp,
                    message=f"Interface {metric.interface} is down",
                ))
                continue

            # Check utilization anomalies
            for util_metric in ["in_utilization", "out_utilization"]:
                baseline = self.get_baseline(device_name, metric.interface, util_metric)
                if not baseline:
                    continue

                current_value = getattr(metric, util_metric)
                anomaly = self._check_anomaly(
                    device_name, metric.interface, util_metric,
                    current_value, baseline, metric.timestamp
                )
                if anomaly:
                    anomalies.append(anomaly)

            # Check error anomalies
            for err_metric in ["in_errors", "out_errors"]:
                baseline = self.get_baseline(device_name, metric.interface, err_metric)
                if not baseline:
                    continue

                current_value = getattr(metric, err_metric)
                anomaly = self._check_anomaly(
                    device_name, metric.interface, err_metric,
                    current_value, baseline, metric.timestamp,
                    is_error_metric=True
                )
                if anomaly:
                    anomalies.append(anomaly)

        # Save anomalies
        for anomaly in anomalies:
            self._save_anomaly(anomaly)

        return anomalies

    def _check_anomaly(
        self,
        device: str,
        interface: str,
        metric_name: str,
        current_value: float,
        baseline: BaselineStats,
        timestamp: str,
        is_error_metric: bool = False,
    ) -> Optional[TrafficAnomaly]:
        """Check if a value is anomalous."""
        if baseline.std_dev == 0:
            return None

        # Calculate z-score
        zscore = (current_value - baseline.mean) / baseline.std_dev

        # Determine anomaly type and severity
        anomaly_type = None
        severity = None
        message = ""

        if abs(zscore) >= ZSCORE_THRESHOLD:
            if is_error_metric:
                if zscore > 0:
                    anomaly_type = AnomalyType.HIGH_ERRORS
                    severity = "high" if zscore > 4 else "medium"
                    message = f"High {metric_name}: {current_value:.0f} (baseline: {baseline.mean:.1f})"
            else:
                if zscore > 0:
                    if "utilization" in metric_name:
                        anomaly_type = AnomalyType.HIGH_UTILIZATION
                        severity = "critical" if current_value > 90 else "high" if current_value > 80 else "medium"
                        message = f"High utilization on {interface}: {current_value:.1f}% (baseline: {baseline.mean:.1f}%)"
                    else:
                        anomaly_type = AnomalyType.TRAFFIC_SPIKE
                        severity = "high" if zscore > 4 else "medium"
                        message = f"Traffic spike on {interface}: {current_value:.1f} (baseline: {baseline.mean:.1f})"
                else:
                    if "utilization" in metric_name:
                        anomaly_type = AnomalyType.LOW_UTILIZATION
                        severity = "low"
                        message = f"Low utilization on {interface}: {current_value:.1f}% (baseline: {baseline.mean:.1f}%)"
                    else:
                        anomaly_type = AnomalyType.TRAFFIC_DROP
                        severity = "medium" if abs(zscore) > 4 else "low"
                        message = f"Traffic drop on {interface}: {current_value:.1f} (baseline: {baseline.mean:.1f})"

        if anomaly_type:
            return TrafficAnomaly(
                device=device,
                interface=interface,
                anomaly_type=anomaly_type,
                metric=metric_name,
                current_value=current_value,
                baseline_mean=baseline.mean,
                baseline_std=baseline.std_dev,
                zscore=zscore,
                severity=severity,
                detected_at=timestamp,
                message=message,
            )

        return None

    def _save_anomaly(self, anomaly: TrafficAnomaly):
        """Save anomaly to database."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO anomalies
                (device, interface, anomaly_type, metric, current_value,
                 baseline_mean, baseline_std, zscore, severity, detected_at, message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly.device, anomaly.interface, anomaly.anomaly_type.value,
                anomaly.metric, anomaly.current_value,
                anomaly.baseline_mean, anomaly.baseline_std, anomaly.zscore,
                anomaly.severity, anomaly.detected_at, anomaly.message,
            ))
            conn.commit()

    def get_recent_anomalies(
        self,
        device: str = None,
        hours: int = 24,
        severity: str = None,
    ) -> list[dict]:
        """Get recent anomalies."""
        cutoff = (now() - timedelta(hours=hours)).isoformat()

        query = "SELECT * FROM anomalies WHERE detected_at >= ?"
        params = [cutoff]

        if device:
            query += " AND device = ?"
            params.append(device)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY detected_at DESC"

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_utilization_summary(self, device: str) -> dict:
        """Get current utilization summary for a device."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row

            # Get latest metrics for each interface
            rows = conn.execute("""
                SELECT interface, in_utilization, out_utilization,
                       in_bps, out_bps, oper_status
                FROM traffic_metrics
                WHERE device = ?
                AND timestamp = (
                    SELECT MAX(timestamp) FROM traffic_metrics WHERE device = ?
                )
            """, (device, device)).fetchall()

            interfaces = []
            for row in rows:
                interfaces.append({
                    "interface": row["interface"],
                    "in_utilization": row["in_utilization"],
                    "out_utilization": row["out_utilization"],
                    "in_mbps": (row["in_bps"] or 0) / 1_000_000,
                    "out_mbps": (row["out_bps"] or 0) / 1_000_000,
                    "status": row["oper_status"],
                })

            return {
                "device": device,
                "interface_count": len(interfaces),
                "interfaces": interfaces,
            }

    async def collect_all_devices(
        self,
        device_names: list[str] = None,
        max_concurrent: int = 5,
    ) -> dict:
        """Collect metrics from multiple devices in parallel."""
        from config.devices import DEVICES

        if device_names is None:
            device_names = [
                name for name, cfg in DEVICES.items()
                if cfg.get("device_type") == "cisco_xe"
            ]

        semaphore = asyncio.Semaphore(max_concurrent)

        async def collect_with_semaphore(device: str):
            async with semaphore:
                try:
                    metrics = await self.collect_metrics(device)
                    return {"device": device, "success": True, "interfaces": len(metrics)}
                except Exception as e:
                    return {"device": device, "success": False, "error": str(e)}

        results = await asyncio.gather(
            *[collect_with_semaphore(d) for d in device_names],
            return_exceptions=True,
        )

        return {
            "collected": sum(1 for r in results if isinstance(r, dict) and r.get("success")),
            "failed": sum(1 for r in results if isinstance(r, dict) and not r.get("success")),
            "results": [r for r in results if isinstance(r, dict)],
        }


# =============================================================================
# Global Instance
# =============================================================================

_baseline: Optional[TrafficBaseline] = None


def get_traffic_baseline() -> TrafficBaseline:
    """Get the global traffic baseline instance."""
    global _baseline
    if _baseline is None:
        _baseline = TrafficBaseline()
    return _baseline
