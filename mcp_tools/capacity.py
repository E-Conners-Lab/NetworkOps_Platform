"""
Capacity and Baseline MCP tools.

This module provides tools for traffic baselining and capacity forecasting:
- baseline_collect: Collect traffic metrics from a device
- baseline_collect_all: Collect from multiple devices
- baseline_calculate: Calculate baseline statistics
- baseline_detect_anomalies: Detect traffic anomalies
- baseline_get_anomalies: Get recent anomalies
- baseline_summary: Get utilization summary
- capacity_collect: Collect capacity metrics
- capacity_forecast_interface: Forecast interface utilization
- capacity_forecast_cpu: Forecast CPU utilization
- capacity_trend: Analyze metric trend
- capacity_recommendations: Get planning recommendations
- capacity_summary: Get overall capacity summary
"""

import json


# =============================================================================
# Traffic Baseline MCP Tool Functions
# =============================================================================

async def baseline_collect(device: str, interfaces: str = None) -> str:
    """
    Collect current traffic metrics from a device.

    Args:
        device: Device name (e.g., "R1")
        interfaces: Comma-separated interface names (optional, all if not specified)

    Returns:
        JSON with collected interface metrics including:
        - Traffic counters (packets, bytes)
        - Rates (bps, pps)
        - Utilization percentages
        - Error counts
    """
    from core.traffic_baseline import get_traffic_baseline

    intf_list = [i.strip() for i in interfaces.split(",")] if interfaces else None

    try:
        baseline = get_traffic_baseline()
        metrics = await baseline.collect_metrics(device, intf_list)

        return json.dumps({
            "device": device,
            "interfaces_collected": len(metrics),
            "metrics": [m.to_dict() for m in metrics],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


async def baseline_collect_all(devices: str = None) -> str:
    """
    Collect traffic metrics from multiple devices in parallel.

    Args:
        devices: Comma-separated device names (optional, all Cisco devices if not specified)

    Returns:
        JSON with collection results per device
    """
    from core.traffic_baseline import get_traffic_baseline

    device_list = [d.strip() for d in devices.split(",")] if devices else None

    try:
        baseline = get_traffic_baseline()
        results = await baseline.collect_all_devices(device_list)

        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def baseline_calculate(device: str, interface: str, days: int = 7) -> str:
    """
    Calculate traffic baseline statistics for an interface.

    Uses historical data to establish normal traffic patterns.
    Requires at least 10 samples collected over time.

    Args:
        device: Device name (e.g., "R1")
        interface: Interface name (e.g., "GigabitEthernet1")
        days: Number of days of historical data to use (default: 7)

    Returns:
        JSON with baseline statistics including:
        - Mean, standard deviation
        - Min/max values
        - Percentiles (25th, 50th, 75th, 95th)
    """
    from core.traffic_baseline import get_traffic_baseline

    try:
        baseline = get_traffic_baseline()
        stats = baseline.calculate_baseline(device, interface, days)

        if not stats:
            return json.dumps({
                "warning": "Insufficient data for baseline",
                "device": device,
                "interface": interface,
                "minimum_samples_required": 10,
            }, indent=2)

        return json.dumps({
            "device": device,
            "interface": interface,
            "period_days": days,
            "baselines": [s.to_dict() for s in stats],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


async def baseline_detect_anomalies(device: str, interfaces: str = None) -> str:
    """
    Detect traffic anomalies by comparing current metrics to baseline.

    Uses z-score (3+ standard deviations) to identify significant deviations.
    Detects: high/low utilization, traffic spikes/drops, high errors, interface down.

    Args:
        device: Device name (e.g., "R1")
        interfaces: Comma-separated interface names (optional, all if not specified)

    Returns:
        JSON with detected anomalies including severity and recommended actions
    """
    from core.traffic_baseline import get_traffic_baseline

    intf_list = [i.strip() for i in interfaces.split(",")] if interfaces else None

    try:
        baseline = get_traffic_baseline()
        anomalies = await baseline.detect_anomalies(device, intf_list)

        # Group by severity
        by_severity = {
            "critical": [a for a in anomalies if a.severity == "critical"],
            "high": [a for a in anomalies if a.severity == "high"],
            "medium": [a for a in anomalies if a.severity == "medium"],
            "low": [a for a in anomalies if a.severity == "low"],
        }

        return json.dumps({
            "device": device,
            "total_anomalies": len(anomalies),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "anomalies": [a.to_dict() for a in anomalies],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


async def baseline_get_anomalies(
    device: str = None,
    hours: int = 24,
    severity: str = None,
) -> str:
    """
    Get recent traffic anomalies from the database.

    Args:
        device: Filter by device name (optional, all if not specified)
        hours: Look back period in hours (default: 24)
        severity: Filter by severity: low, medium, high, critical (optional)

    Returns:
        JSON with historical anomaly records
    """
    from core.traffic_baseline import get_traffic_baseline

    try:
        baseline = get_traffic_baseline()
        anomalies = baseline.get_recent_anomalies(device, hours, severity)

        return json.dumps({
            "period_hours": hours,
            "device_filter": device,
            "severity_filter": severity,
            "count": len(anomalies),
            "anomalies": anomalies,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def baseline_summary(device: str) -> str:
    """
    Get current utilization summary for a device.

    Shows the most recent traffic metrics for each interface.

    Args:
        device: Device name (e.g., "R1")

    Returns:
        JSON with per-interface utilization and throughput
    """
    from core.traffic_baseline import get_traffic_baseline

    try:
        baseline = get_traffic_baseline()
        summary = baseline.get_utilization_summary(device)

        return json.dumps(summary, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


# =============================================================================
# Capacity Forecasting MCP Tool Functions
# =============================================================================

async def capacity_collect(device: str) -> str:
    """
    Collect current capacity metrics from a device.

    Collects CPU, memory, and interface utilization for trend analysis.
    Run regularly (hourly/daily) to build historical data for forecasting.

    Args:
        device: Device name (e.g., "R1")

    Returns:
        JSON confirming metrics collected
    """
    from core.capacity_forecast import get_capacity_forecaster

    try:
        forecaster = get_capacity_forecaster()
        await forecaster.collect_current_metrics(device)

        return json.dumps({
            "device": device,
            "status": "success",
            "message": "Capacity metrics collected successfully",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


async def capacity_forecast_interface(
    device: str,
    interface: str,
    history_days: int = 30,
    forecast_days: int = 90,
) -> str:
    """
    Forecast interface utilization based on historical trends.

    Args:
        device: Device name (e.g., "R1")
        interface: Interface name (e.g., "GigabitEthernet1")
        history_days: Days of historical data to analyze (default: 30)
        forecast_days: Days into the future to forecast (default: 90)

    Returns:
        JSON with forecast including trend, projections, and threshold warnings
    """
    from core.capacity_forecast import get_capacity_forecaster

    try:
        forecaster = get_capacity_forecaster()
        forecast = forecaster.forecast_utilization(
            device, interface, history_days, forecast_days
        )

        if not forecast:
            return json.dumps({
                "warning": "Insufficient data for forecasting",
                "device": device,
                "interface": interface,
                "hint": "Run capacity_collect regularly to build historical data",
            }, indent=2)

        return json.dumps(forecast.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def capacity_forecast_cpu(
    device: str,
    history_days: int = 30,
    forecast_days: int = 90,
) -> str:
    """
    Forecast CPU utilization based on historical trends.

    Args:
        device: Device name (e.g., "R1")
        history_days: Days of historical data to analyze (default: 30)
        forecast_days: Days into the future to forecast (default: 90)

    Returns:
        JSON with CPU forecast and threshold warnings
    """
    from core.capacity_forecast import get_capacity_forecaster

    try:
        forecaster = get_capacity_forecaster()
        forecast = forecaster.forecast_cpu(device, history_days, forecast_days)

        if not forecast:
            return json.dumps({
                "warning": "Insufficient data for forecasting",
                "device": device,
                "hint": "Run capacity_collect regularly to build historical data",
            }, indent=2)

        return json.dumps(forecast.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def capacity_trend(
    device: str,
    metric: str,
    interface: str = None,
    days: int = 30,
) -> str:
    """
    Analyze the trend of a specific metric.

    Args:
        device: Device name
        metric: Metric type (utilization_in, utilization_out, cpu, memory)
        interface: Interface name (required for utilization metrics)
        days: Days of data to analyze (default: 30)

    Returns:
        JSON with trend analysis (direction, slope, projections)
    """
    from core.capacity_forecast import get_capacity_forecaster, MetricType

    valid_metrics = ["utilization_in", "utilization_out", "cpu", "memory"]
    if metric not in valid_metrics:
        return json.dumps({
            "error": f"Invalid metric. Must be one of: {valid_metrics}"
        }, indent=2)

    try:
        forecaster = get_capacity_forecaster()
        trend = forecaster.analyze_trend(
            device, MetricType(metric), interface, days
        )

        if not trend:
            return json.dumps({
                "warning": "Insufficient data for trend analysis",
                "device": device,
                "metric": metric,
            }, indent=2)

        return json.dumps(trend.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def capacity_recommendations(
    device: str = None,
    severity: str = None,
) -> str:
    """
    Get capacity planning recommendations.

    Analyzes current trends and provides actionable recommendations
    for capacity planning and upgrades.

    Args:
        device: Filter by device (optional, all devices if not specified)
        severity: Filter by severity: critical, warning, info (optional)

    Returns:
        JSON with prioritized recommendations and action items
    """
    from core.capacity_forecast import get_capacity_forecaster

    try:
        forecaster = get_capacity_forecaster()
        recommendations = forecaster.get_recommendations(device, severity)

        return json.dumps({
            "count": len(recommendations),
            "recommendations": [r.to_dict() for r in recommendations],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def capacity_summary() -> str:
    """
    Get overall capacity summary across all devices.

    Returns high-level capacity health status for the network.

    Returns:
        JSON with capacity summary including issue counts and at-risk devices
    """
    from core.capacity_forecast import get_capacity_forecaster

    try:
        forecaster = get_capacity_forecaster()
        summary = forecaster.get_capacity_summary()

        return json.dumps(summary, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    # Traffic baseline tools (6)
    {"fn": baseline_collect, "name": "baseline_collect", "category": "capacity"},
    {"fn": baseline_collect_all, "name": "baseline_collect_all", "category": "capacity"},
    {"fn": baseline_calculate, "name": "baseline_calculate", "category": "capacity"},
    {"fn": baseline_detect_anomalies, "name": "baseline_detect_anomalies", "category": "capacity"},
    {"fn": baseline_get_anomalies, "name": "baseline_get_anomalies", "category": "capacity"},
    {"fn": baseline_summary, "name": "baseline_summary", "category": "capacity"},
    # Capacity forecasting tools (6)
    {"fn": capacity_collect, "name": "capacity_collect", "category": "capacity"},
    {"fn": capacity_forecast_interface, "name": "capacity_forecast_interface", "category": "capacity"},
    {"fn": capacity_forecast_cpu, "name": "capacity_forecast_cpu", "category": "capacity"},
    {"fn": capacity_trend, "name": "capacity_trend", "category": "capacity"},
    {"fn": capacity_recommendations, "name": "capacity_recommendations", "category": "capacity"},
    {"fn": capacity_summary, "name": "capacity_summary", "category": "capacity"},
]
