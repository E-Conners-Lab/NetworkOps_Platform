"""
Capacity Forecasting for NetworkOps.

Analyzes historical traffic data to forecast future capacity needs
and identify potential bottlenecks before they impact the network.

Features:
- Trend analysis using linear regression
- Seasonal pattern detection
- Threshold breach prediction
- Capacity planning recommendations
- Multi-metric forecasting (bandwidth, CPU, memory)

Usage:
    from core.capacity_forecast import CapacityForecaster

    forecaster = CapacityForecaster()

    # Forecast interface utilization
    forecast = forecaster.forecast_utilization("R1", "GigabitEthernet1", days=30)

    # Get capacity recommendations
    recommendations = forecaster.get_recommendations("R1")
"""

import json
import logging
import math
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from core.timestamps import now, isonow
from enum import Enum
from pathlib import Path
from typing import Optional

from core.db import DatabaseManager

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================


# Thresholds for capacity warnings
UTILIZATION_WARNING_THRESHOLD = 70  # Percent
UTILIZATION_CRITICAL_THRESHOLD = 85  # Percent
CPU_WARNING_THRESHOLD = 60  # Percent
CPU_CRITICAL_THRESHOLD = 80  # Percent
MEMORY_WARNING_THRESHOLD = 75  # Percent
MEMORY_CRITICAL_THRESHOLD = 90  # Percent


# =============================================================================
# Data Models
# =============================================================================

class MetricType(str, Enum):
    BANDWIDTH_IN = "bandwidth_in"
    BANDWIDTH_OUT = "bandwidth_out"
    UTILIZATION_IN = "utilization_in"
    UTILIZATION_OUT = "utilization_out"
    CPU = "cpu"
    MEMORY = "memory"
    ERROR_RATE = "error_rate"


class TrendDirection(str, Enum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class TrendAnalysis:
    """Result of trend analysis."""
    metric: str
    direction: TrendDirection
    slope: float  # Change per day
    r_squared: float  # Fit quality (0-1)
    current_value: float
    projected_30d: float
    projected_90d: float

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "direction": self.direction.value,
        }


@dataclass
class CapacityForecast:
    """Capacity forecast for an interface/resource."""
    device: str
    interface: str
    metric: MetricType
    current_value: float
    trend: TrendAnalysis
    threshold_warning: float
    threshold_critical: float
    days_to_warning: Optional[int]
    days_to_critical: Optional[int]
    forecast_values: list[dict]  # [{day: N, value: X}, ...]
    confidence: float  # 0-1 based on data quality

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "metric": self.metric.value,
            "trend": self.trend.to_dict(),
        }


@dataclass
class CapacityRecommendation:
    """Capacity planning recommendation."""
    device: str
    interface: str
    metric: str
    severity: Severity
    title: str
    description: str
    current_value: float
    projected_value: float
    days_until_threshold: Optional[int]
    action_items: list[str]

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "severity": self.severity.value,
        }


# =============================================================================
# Capacity Forecaster
# =============================================================================

class CapacityForecaster:
    """
    Analyzes capacity trends and generates forecasts.
    """

    def __init__(self, db_path: Path = None):
        self._dm = DatabaseManager.get_instance()

    def record_metric(
        self,
        device: str,
        metric_type: MetricType,
        value: float,
        interface: str = None,
        timestamp: str = None,
    ):
        """Record a capacity metric for historical analysis."""
        if timestamp is None:
            timestamp = isonow()

        with self._dm.connect() as conn:
            conn.execute("""
                INSERT INTO capacity_metrics (device, interface, metric_type, value, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (device, interface, metric_type.value, value, timestamp))

    def get_historical_data(
        self,
        device: str,
        metric_type: MetricType,
        interface: str = None,
        days: int = 30,
    ) -> list[tuple[str, float]]:
        """Get historical data for analysis."""
        cutoff = (now() - timedelta(days=days)).isoformat()

        query = """
            SELECT timestamp, value FROM capacity_metrics
            WHERE device = ? AND metric_type = ? AND timestamp >= ?
        """
        params = [device, metric_type.value, cutoff]

        if interface:
            query += " AND interface = ?"
            params.append(interface)

        query += " ORDER BY timestamp"

        with self._dm.connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [(r[0], r[1]) for r in rows]

    def analyze_trend(
        self,
        device: str,
        metric_type: MetricType,
        interface: str = None,
        days: int = 30,
    ) -> Optional[TrendAnalysis]:
        """
        Analyze the trend of a metric using linear regression.
        """
        data = self.get_historical_data(device, metric_type, interface, days)

        if len(data) < 3:
            logger.warning(f"Insufficient data for trend analysis: {len(data)} points")
            return None

        # Convert to numerical values for regression
        base_time = datetime.fromisoformat(data[0][0])
        x_values = []  # Days from start
        y_values = []  # Metric values

        for timestamp, value in data:
            t = datetime.fromisoformat(timestamp)
            days_from_start = (t - base_time).total_seconds() / 86400
            x_values.append(days_from_start)
            y_values.append(value)

        # Linear regression: y = mx + b
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)

        # Calculate slope (m) and intercept (b)
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0
            intercept = sum_y / n
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator
            intercept = (sum_y - slope * sum_x) / n

        # Calculate R-squared (coefficient of determination)
        y_mean = sum_y / n
        ss_tot = sum((y - y_mean) ** 2 for y in y_values)
        ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(x_values, y_values))
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0

        # Determine trend direction
        if abs(slope) < 0.1:  # Less than 0.1% change per day
            direction = TrendDirection.STABLE
        elif slope > 0:
            direction = TrendDirection.INCREASING
        else:
            direction = TrendDirection.DECREASING

        # Project values
        current_value = y_values[-1]
        latest_x = x_values[-1]
        projected_30d = slope * (latest_x + 30) + intercept
        projected_90d = slope * (latest_x + 90) + intercept

        return TrendAnalysis(
            metric=metric_type.value,
            direction=direction,
            slope=slope,
            r_squared=max(0, min(1, r_squared)),
            current_value=current_value,
            projected_30d=max(0, projected_30d),
            projected_90d=max(0, projected_90d),
        )

    def forecast_utilization(
        self,
        device: str,
        interface: str,
        days: int = 30,
        forecast_days: int = 90,
    ) -> Optional[CapacityForecast]:
        """
        Forecast interface utilization.
        """
        # Analyze trend for inbound utilization
        trend = self.analyze_trend(
            device, MetricType.UTILIZATION_IN, interface, days
        )

        if not trend:
            return None

        # Calculate days to thresholds
        days_to_warning = None
        days_to_critical = None

        if trend.direction == TrendDirection.INCREASING and trend.slope > 0:
            # Days = (threshold - current) / slope
            if trend.current_value < UTILIZATION_WARNING_THRESHOLD:
                days_to_warning = int(
                    (UTILIZATION_WARNING_THRESHOLD - trend.current_value) / trend.slope
                )
            if trend.current_value < UTILIZATION_CRITICAL_THRESHOLD:
                days_to_critical = int(
                    (UTILIZATION_CRITICAL_THRESHOLD - trend.current_value) / trend.slope
                )

        # Generate forecast values
        forecast_values = []
        for day in range(1, forecast_days + 1, 7):  # Weekly points
            projected = trend.current_value + (trend.slope * day)
            forecast_values.append({
                "day": day,
                "value": max(0, min(100, projected)),  # Clamp to 0-100%
            })

        # Calculate confidence based on R-squared and data points
        data = self.get_historical_data(device, MetricType.UTILIZATION_IN, interface, days)
        data_quality = min(1.0, len(data) / 100)  # More data = higher confidence
        confidence = trend.r_squared * data_quality

        return CapacityForecast(
            device=device,
            interface=interface,
            metric=MetricType.UTILIZATION_IN,
            current_value=trend.current_value,
            trend=trend,
            threshold_warning=UTILIZATION_WARNING_THRESHOLD,
            threshold_critical=UTILIZATION_CRITICAL_THRESHOLD,
            days_to_warning=days_to_warning if days_to_warning and days_to_warning > 0 else None,
            days_to_critical=days_to_critical if days_to_critical and days_to_critical > 0 else None,
            forecast_values=forecast_values,
            confidence=confidence,
        )

    def forecast_cpu(
        self,
        device: str,
        days: int = 30,
        forecast_days: int = 90,
    ) -> Optional[CapacityForecast]:
        """
        Forecast CPU utilization.
        """
        trend = self.analyze_trend(device, MetricType.CPU, days=days)

        if not trend:
            return None

        days_to_warning = None
        days_to_critical = None

        if trend.direction == TrendDirection.INCREASING and trend.slope > 0:
            if trend.current_value < CPU_WARNING_THRESHOLD:
                days_to_warning = int(
                    (CPU_WARNING_THRESHOLD - trend.current_value) / trend.slope
                )
            if trend.current_value < CPU_CRITICAL_THRESHOLD:
                days_to_critical = int(
                    (CPU_CRITICAL_THRESHOLD - trend.current_value) / trend.slope
                )

        forecast_values = []
        for day in range(1, forecast_days + 1, 7):
            projected = trend.current_value + (trend.slope * day)
            forecast_values.append({
                "day": day,
                "value": max(0, min(100, projected)),
            })

        data = self.get_historical_data(device, MetricType.CPU, days=days)
        confidence = trend.r_squared * min(1.0, len(data) / 100)

        return CapacityForecast(
            device=device,
            interface=None,
            metric=MetricType.CPU,
            current_value=trend.current_value,
            trend=trend,
            threshold_warning=CPU_WARNING_THRESHOLD,
            threshold_critical=CPU_CRITICAL_THRESHOLD,
            days_to_warning=days_to_warning if days_to_warning and days_to_warning > 0 else None,
            days_to_critical=days_to_critical if days_to_critical and days_to_critical > 0 else None,
            forecast_values=forecast_values,
            confidence=confidence,
        )

    def get_recommendations(
        self,
        device: str = None,
        severity_filter: str = None,
    ) -> list[CapacityRecommendation]:
        """
        Generate capacity planning recommendations.
        """
        from config.devices import DEVICES

        recommendations = []
        devices_to_check = [device] if device else [
            d for d, cfg in DEVICES.items()
            if cfg.get("device_type") == "cisco_xe"
        ]

        for dev in devices_to_check:
            # Check CPU trend
            cpu_trend = self.analyze_trend(dev, MetricType.CPU, days=14)
            if cpu_trend:
                rec = self._generate_cpu_recommendation(dev, cpu_trend)
                if rec:
                    recommendations.append(rec)

            # Check memory trend
            mem_trend = self.analyze_trend(dev, MetricType.MEMORY, days=14)
            if mem_trend:
                rec = self._generate_memory_recommendation(dev, mem_trend)
                if rec:
                    recommendations.append(rec)

            # Check interface utilization
            interfaces = self._get_device_interfaces(dev)
            for intf in interfaces:
                util_trend = self.analyze_trend(
                    dev, MetricType.UTILIZATION_IN, intf, days=14
                )
                if util_trend:
                    rec = self._generate_utilization_recommendation(dev, intf, util_trend)
                    if rec:
                        recommendations.append(rec)

        # Filter by severity if specified
        if severity_filter:
            recommendations = [
                r for r in recommendations
                if r.severity.value == severity_filter
            ]

        # Sort by severity (critical first)
        severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        recommendations.sort(key=lambda r: severity_order[r.severity])

        return recommendations

    def _get_device_interfaces(self, device: str) -> list[str]:
        """Get interfaces with historical data for a device."""
        with self._dm.connect() as conn:
            rows = conn.execute("""
                SELECT DISTINCT interface FROM capacity_metrics
                WHERE device = ? AND interface IS NOT NULL
            """, (device,)).fetchall()
            return [r[0] for r in rows]

    def _generate_cpu_recommendation(
        self,
        device: str,
        trend: TrendAnalysis,
    ) -> Optional[CapacityRecommendation]:
        """Generate CPU capacity recommendation."""
        if trend.current_value >= CPU_CRITICAL_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=None,
                metric="CPU",
                severity=Severity.CRITICAL,
                title="Critical CPU utilization",
                description=f"CPU is at {trend.current_value:.1f}%, above critical threshold",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=0,
                action_items=[
                    "Identify high-CPU processes immediately",
                    "Consider offloading traffic or services",
                    "Plan for hardware upgrade if persistent",
                ],
            )
        elif trend.current_value >= CPU_WARNING_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=None,
                metric="CPU",
                severity=Severity.WARNING,
                title="High CPU utilization",
                description=f"CPU is at {trend.current_value:.1f}%, trending {trend.direction.value}",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=None,
                action_items=[
                    "Monitor CPU trend over next week",
                    "Identify top CPU consumers",
                    "Consider optimization or load balancing",
                ],
            )
        elif (
            trend.direction == TrendDirection.INCREASING
            and trend.projected_30d >= CPU_WARNING_THRESHOLD
        ):
            days_to_warning = int(
                (CPU_WARNING_THRESHOLD - trend.current_value) / trend.slope
            ) if trend.slope > 0 else None

            return CapacityRecommendation(
                device=device,
                interface=None,
                metric="CPU",
                severity=Severity.INFO,
                title="CPU trending upward",
                description=f"CPU at {trend.current_value:.1f}%, projected to reach {trend.projected_30d:.1f}% in 30 days",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=days_to_warning,
                action_items=[
                    "Track CPU usage weekly",
                    "Plan capacity review before threshold",
                ],
            )

        return None

    def _generate_memory_recommendation(
        self,
        device: str,
        trend: TrendAnalysis,
    ) -> Optional[CapacityRecommendation]:
        """Generate memory capacity recommendation."""
        if trend.current_value >= MEMORY_CRITICAL_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=None,
                metric="Memory",
                severity=Severity.CRITICAL,
                title="Critical memory utilization",
                description=f"Memory is at {trend.current_value:.1f}%, risk of OOM",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=0,
                action_items=[
                    "Clear caches and buffers immediately",
                    "Check for memory leaks",
                    "Plan emergency maintenance window",
                ],
            )
        elif trend.current_value >= MEMORY_WARNING_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=None,
                metric="Memory",
                severity=Severity.WARNING,
                title="High memory utilization",
                description=f"Memory is at {trend.current_value:.1f}%",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=None,
                action_items=[
                    "Monitor memory trend",
                    "Review running processes",
                    "Consider memory upgrade",
                ],
            )

        return None

    def _generate_utilization_recommendation(
        self,
        device: str,
        interface: str,
        trend: TrendAnalysis,
    ) -> Optional[CapacityRecommendation]:
        """Generate interface utilization recommendation."""
        if trend.current_value >= UTILIZATION_CRITICAL_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=interface,
                metric="Bandwidth",
                severity=Severity.CRITICAL,
                title=f"Critical bandwidth on {interface}",
                description=f"Utilization at {trend.current_value:.1f}%, congestion likely",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=0,
                action_items=[
                    "Implement QoS policies immediately",
                    "Identify top talkers",
                    "Plan link upgrade or load balancing",
                ],
            )
        elif trend.current_value >= UTILIZATION_WARNING_THRESHOLD:
            return CapacityRecommendation(
                device=device,
                interface=interface,
                metric="Bandwidth",
                severity=Severity.WARNING,
                title=f"High bandwidth on {interface}",
                description=f"Utilization at {trend.current_value:.1f}%, monitor closely",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=None,
                action_items=[
                    "Review traffic patterns",
                    "Consider traffic engineering",
                    "Plan for potential upgrade",
                ],
            )
        elif (
            trend.direction == TrendDirection.INCREASING
            and trend.projected_30d >= UTILIZATION_WARNING_THRESHOLD
        ):
            days_to_warning = int(
                (UTILIZATION_WARNING_THRESHOLD - trend.current_value) / trend.slope
            ) if trend.slope > 0 else None

            return CapacityRecommendation(
                device=device,
                interface=interface,
                metric="Bandwidth",
                severity=Severity.INFO,
                title=f"Bandwidth trend on {interface}",
                description=f"Projected to reach {trend.projected_30d:.1f}% in 30 days",
                current_value=trend.current_value,
                projected_value=trend.projected_30d,
                days_until_threshold=days_to_warning,
                action_items=[
                    "Track utilization weekly",
                    "Plan capacity review",
                ],
            )

        return None

    def get_capacity_summary(self) -> dict:
        """Get overall capacity summary across all devices."""
        from config.devices import DEVICES

        summary = {
            "devices_analyzed": 0,
            "interfaces_analyzed": 0,
            "critical_issues": 0,
            "warning_issues": 0,
            "info_issues": 0,
            "devices_at_risk": [],
            "interfaces_at_risk": [],
        }

        devices = [
            d for d, cfg in DEVICES.items()
            if cfg.get("device_type") == "cisco_xe"
        ]

        for device in devices:
            recommendations = self.get_recommendations(device)
            summary["devices_analyzed"] += 1

            for rec in recommendations:
                if rec.severity == Severity.CRITICAL:
                    summary["critical_issues"] += 1
                    if device not in summary["devices_at_risk"]:
                        summary["devices_at_risk"].append(device)
                    if rec.interface:
                        summary["interfaces_at_risk"].append(
                            f"{device}:{rec.interface}"
                        )
                elif rec.severity == Severity.WARNING:
                    summary["warning_issues"] += 1
                else:
                    summary["info_issues"] += 1

        summary["interfaces_analyzed"] = len(
            set(i.split(":")[1] for i in summary["interfaces_at_risk"])
        )

        return summary

    async def collect_current_metrics(self, device: str):
        """
        Collect and record current capacity metrics from a device.
        """
        from core.scrapli_manager import get_ios_xe_connection
        from config.devices import DEVICES

        if device not in DEVICES:
            raise ValueError(f"Device '{device}' not found")

        timestamp = isonow()

        async with get_ios_xe_connection(device) as conn:
            # Get CPU utilization
            resp = await conn.send_command(
                "show processes cpu | include CPU utilization"
            )
            cpu = self._parse_cpu(resp.result)
            if cpu is not None:
                self.record_metric(device, MetricType.CPU, cpu, timestamp=timestamp)

            # Get memory utilization
            resp = await conn.send_command("show memory statistics | include Processor")
            memory = self._parse_memory(resp.result)
            if memory is not None:
                self.record_metric(device, MetricType.MEMORY, memory, timestamp=timestamp)

            # Get interface utilization
            resp = await conn.send_command("show interfaces")
            interfaces = self._parse_interface_utilization(resp.result)
            for intf, util_in, util_out in interfaces:
                self.record_metric(
                    device, MetricType.UTILIZATION_IN, util_in,
                    interface=intf, timestamp=timestamp
                )
                self.record_metric(
                    device, MetricType.UTILIZATION_OUT, util_out,
                    interface=intf, timestamp=timestamp
                )

    def _parse_cpu(self, output: str) -> Optional[float]:
        """Parse CPU utilization from show output."""
        import re
        match = re.search(r"one minute:\s*(\d+)%", output)
        if match:
            return float(match.group(1))
        return None

    def _parse_memory(self, output: str) -> Optional[float]:
        """Parse memory utilization from show output."""
        import re
        # Match: Processor   Total Used Free ...
        match = re.search(r"Processor\s+(\d+)\s+(\d+)\s+(\d+)", output)
        if match:
            total = int(match.group(1))
            used = int(match.group(2))
            if total > 0:
                return (used / total) * 100
        return None

    def _parse_interface_utilization(
        self,
        output: str,
    ) -> list[tuple[str, float, float]]:
        """Parse interface utilization from show interfaces."""
        import re
        results = []
        current_intf = None
        speed = 0

        for line in output.split("\n"):
            # Interface line
            intf_match = re.match(r"^(Gi\S+|Eth\S+|Te\S+)\s+is", line)
            if intf_match:
                current_intf = intf_match.group(1)
                continue

            if not current_intf:
                continue

            # Speed line
            speed_match = re.search(r"BW (\d+) Kbit", line)
            if speed_match:
                speed = int(speed_match.group(1)) * 1000  # Convert to bps

            # Input rate
            in_rate_match = re.search(
                r"input rate (\d+) bits/sec",
                line
            )
            if in_rate_match and speed > 0:
                in_bps = int(in_rate_match.group(1))
                util_in = (in_bps / speed) * 100

            # Output rate
            out_rate_match = re.search(
                r"output rate (\d+) bits/sec",
                line
            )
            if out_rate_match and speed > 0:
                out_bps = int(out_rate_match.group(1))
                util_out = (out_bps / speed) * 100

                # Skip management interfaces
                if "Gi4" not in current_intf and "GigabitEthernet4" not in current_intf:
                    results.append((current_intf, util_in, util_out))

                current_intf = None
                speed = 0

        return results


# =============================================================================
# Global Instance
# =============================================================================

_forecaster: Optional[CapacityForecaster] = None


def get_capacity_forecaster() -> CapacityForecaster:
    """Get the global capacity forecaster instance."""
    global _forecaster
    if _forecaster is None:
        _forecaster = CapacityForecaster()
    return _forecaster
