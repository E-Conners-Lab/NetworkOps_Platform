"""
Impact Analysis MCP Tools.

Pre-change impact analysis for network configuration changes:
- impact_analyze: Analyze impact of shutting down an interface
- impact_status: Check if impact analysis is enabled

These tools allow the AI assistant to understand the consequences of
configuration changes BEFORE executing them, enabling safer automation.
"""

import json
import asyncio
from typing import Optional

from config.devices import DEVICES
from core.feature_flags import is_enabled, get_impact_analysis_config


async def impact_analyze(
    device: str,
    interface: str,
    command: str = "shutdown",
    refresh_data: bool = True,
) -> str:
    """
    Analyze the impact of shutting down an interface before making changes.

    This is a CRITICAL safety tool. Always run this before suggesting or
    executing interface shutdown commands to understand the consequences.

    Args:
        device: Device name (e.g., "R1", "edge1", "spine1")
        interface: Interface name (e.g., "GigabitEthernet2", "eth0", "ethernet-1/1")
        command: Command to analyze (currently only "shutdown" supported)
        refresh_data: Whether to collect fresh data from device (default: True)

    Returns:
        JSON with impact analysis results including:
        - risk_category: NO_IMPACT, LOW, MEDIUM, HIGH, or CRITICAL
        - current_state: Interface status and IP address
        - impact:
            - ospf_adjacencies_lost: List of OSPF neighbors that would go down
            - bgp_peers_lost: List of BGP peers that would disconnect
            - routes_removed: List of routes that would be withdrawn
            - summary: Counts of affected adjacencies and routes
        - warnings: List of warning messages
        - data_quality: Confidence level of the analysis

    Risk Categories:
        - NO_IMPACT: Interface is down or has no routing impact
        - LOW: Minor impact, alternate paths exist
        - MEDIUM: Some routes affected, most have alternates
        - HIGH: Significant routing impact, some routes have no alternates
        - CRITICAL: Major outage risk, critical routes have no alternates

    Examples:
        # Check before shutting down a WAN link
        impact_analyze("R1", "GigabitEthernet2")

        # Check containerlab FRR device
        impact_analyze("edge1", "eth0")

        # Check Nokia SR Linux device
        impact_analyze("spine1", "ethernet-1/1")

    Usage Pattern:
        1. User asks to shut down an interface
        2. AI runs impact_analyze() first
        3. If HIGH/CRITICAL risk, AI warns user and asks for confirmation
        4. If user confirms, AI proceeds with the change
    """
    # Check if feature is enabled
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
            "suggestion": "Enable impact_analysis in feature_flags.yaml or set FF_IMPACT_ANALYSIS_ENABLED=true"
        }, indent=2)

    # Validate device exists
    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
            "available_devices": list(DEVICES.keys())[:10]  # Show first 10
        }, indent=2)

    # Import here to avoid circular imports
    from core.impact_analyzer import ImpactAnalyzer

    try:
        analyzer = ImpactAnalyzer()
        result = await analyzer.analyze(
            device=device,
            interface=interface,
            command=command,
            refresh_data=refresh_data,
        )

        # Convert dataclass to dict for JSON serialization
        return json.dumps(result.to_dict(), indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
            "interface": interface,
        }, indent=2)


async def impact_status() -> str:
    """
    Check if impact analysis is enabled and get configuration.

    Returns:
        JSON with:
        - enabled: Whether impact analysis is enabled
        - supported_platforms: List of supported device platforms
        - config: Analysis configuration (timeouts, rate limits, etc.)

    Example:
        impact_status()
        # Returns: {"enabled": true, "supported_platforms": ["cisco_xe", "frr", "srlinux"], ...}
    """
    config = get_impact_analysis_config()

    return json.dumps({
        "enabled": is_enabled("impact_analysis_enabled"),
        "supported_platforms": config.get("supported_platforms", []),
        "config": {
            "analysis_timeout_sec": config.get("analysis_timeout_sec", 10),
            "data_max_age_sec": config.get("data_max_age_sec", 300),
            "rate_limit_per_device_per_minute": config.get("rate_limit_per_device_per_minute", 2),
        }
    }, indent=2)


async def impact_check_interface(device: str, interface: str) -> str:
    """
    Quick check if an interface can be analyzed and get current state.

    Use this for a fast preliminary check before full impact analysis.
    Does NOT collect routing data - just checks interface status.

    Args:
        device: Device name
        interface: Interface name

    Returns:
        JSON with:
        - can_analyze: Whether full analysis is possible
        - platform: Detected platform type
        - interface_status: Current interface state (if reachable)

    Example:
        impact_check_interface("R1", "GigabitEthernet2")
    """
    if device not in DEVICES:
        return json.dumps({
            "can_analyze": False,
            "reason": f"Device '{device}' not found"
        }, indent=2)

    device_info = DEVICES[device]
    device_type = device_info.get("device_type", "unknown")

    # Determine platform
    if device_type in ("cisco_xe", "cisco_ios"):
        platform = "cisco_xe"
    elif "frr" in device_type:
        platform = "frr"
    elif "srlinux" in device_type:
        platform = "srlinux"
    else:
        platform = "unknown"

    # Check if platform is supported
    config = get_impact_analysis_config()
    supported = config.get("supported_platforms", ["cisco_xe"])

    if platform not in supported:
        return json.dumps({
            "can_analyze": False,
            "reason": f"Platform '{platform}' not supported",
            "supported_platforms": supported,
            "device": device,
            "interface": interface,
        }, indent=2)

    return json.dumps({
        "can_analyze": True,
        "device": device,
        "interface": interface,
        "platform": platform,
        "device_type": device_type,
        "host": device_info.get("host"),
    }, indent=2)


# =============================================================================
# Trending Tools
# =============================================================================


async def impact_snapshot(device: str, notes: Optional[str] = None) -> str:
    """
    Capture current device state as a snapshot for trending/baseline comparison.

    Collects OSPF neighbors, BGP peers, and route counts at a point in time.
    Use these snapshots to track state changes over time or set baselines.

    Args:
        device: Device name (e.g., "R1", "edge1")
        notes: Optional notes about this snapshot (e.g., "Pre-maintenance")

    Returns:
        JSON with snapshot details including:
        - snapshot_id: Unique identifier for this snapshot
        - timestamp: When snapshot was captured
        - ospf_neighbors: List of OSPF adjacencies
        - bgp_peers: List of BGP peer states
        - route_count: Total routes in routing table

    Examples:
        # Capture snapshot before maintenance
        impact_snapshot("R1", notes="Pre-maintenance window")

        # Capture for baseline comparison
        impact_snapshot("R2")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()
        snapshot = await trending.capture_snapshot(device, notes=notes)

        return json.dumps({
            "status": "success",
            "snapshot": snapshot.to_dict(),
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def impact_baseline_set(
    device: str,
    snapshot_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> str:
    """
    Set a snapshot as the baseline for drift detection.

    The baseline represents the expected "known good" state for a device.
    Future drift checks compare current state against this baseline.

    Args:
        device: Device name
        snapshot_id: Snapshot ID to use as baseline. If not provided,
                     captures a new snapshot and uses it.
        reason: Reason for setting this baseline (e.g., "Post-upgrade validation")

    Returns:
        JSON with baseline details

    Examples:
        # Set existing snapshot as baseline
        impact_baseline_set("R1", snapshot_id="abc123", reason="Known good state")

        # Capture new snapshot and set as baseline
        impact_baseline_set("R1", reason="Initial baseline after deployment")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()

        # If no snapshot_id provided, capture new one
        if snapshot_id is None:
            snapshot = await trending.capture_snapshot(device, notes="Baseline capture")
            snapshot_id = snapshot.snapshot_id

        trending.set_baseline(device, snapshot_id, set_by="mcp_tool", reason=reason)
        baseline = trending.get_baseline(device)

        return json.dumps({
            "status": "success",
            "message": f"Baseline set for {device}",
            "baseline": baseline.to_dict() if baseline else None,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def impact_baseline_get(device: str) -> str:
    """
    Get the current baseline snapshot for a device.

    Args:
        device: Device name

    Returns:
        JSON with baseline details or message if no baseline set

    Example:
        impact_baseline_get("R1")
    """
    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()
        baseline = trending.get_baseline(device)

        if baseline is None:
            return json.dumps({
                "status": "no_baseline",
                "device": device,
                "message": f"No baseline set for {device}. Use impact_baseline_set() to create one.",
            }, indent=2)

        return json.dumps({
            "status": "success",
            "baseline": baseline.to_dict(),
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def impact_drift_check(device: str) -> str:
    """
    Check for drift between current device state and its baseline.

    Compares current OSPF neighbors, BGP peers, and route counts against
    the stored baseline to detect configuration drift or outages.

    Args:
        device: Device name

    Returns:
        JSON with drift report including:
        - total_drifts: Number of changes detected
        - critical_count: Number of critical changes (outage risk)
        - warning_count: Number of warning changes
        - drifts: List of individual changes with details
        - summary: Human-readable summary

    Drift Types:
        - ospf_neighbor_lost: OSPF adjacency went down
        - bgp_peer_lost: BGP peer went down
        - route_count_changed: Significant change in route count

    Examples:
        # Check for drift from baseline
        impact_drift_check("R1")

    Usage Pattern:
        1. Set baseline when device is in known good state
        2. Periodically run drift_check to detect changes
        3. Review and resolve critical/warning drifts
        4. Update baseline after intentional changes
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()

        # Check if baseline exists
        baseline = trending.get_baseline(device)
        if baseline is None:
            return json.dumps({
                "status": "no_baseline",
                "device": device,
                "message": f"No baseline set for {device}. Use impact_baseline_set() first.",
            }, indent=2)

        report = await trending.compare_to_baseline(device)

        return json.dumps({
            "status": "success",
            "report": report.to_dict(),
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def impact_trending_summary(device: str, days: int = 7) -> str:
    """
    Get trending summary for a device over time.

    Shows snapshot counts, drift history, and current state overview.

    Args:
        device: Device name
        days: Number of days to look back (default: 7)

    Returns:
        JSON with:
        - snapshot_count: Number of snapshots captured
        - has_baseline: Whether a baseline is set
        - drift_counts: Counts by severity
        - latest_state: Most recent captured state

    Example:
        impact_trending_summary("R1", days=30)
    """
    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()
        summary = trending.get_trending_summary(device, days=days)

        return json.dumps({
            "status": "success",
            "summary": summary,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


# =============================================================================
# Intent Validation Tools
# =============================================================================


async def intent_validate(device: str) -> str:
    """
    Validate a device against its YAML intent definition.

    Compares live OSPF/BGP/interface state against declared expected state.
    Reports any violations where reality doesn't match intent.

    Args:
        device: Device name (e.g., "R3", "edge1")

    Returns:
        JSON with validation results including any violations

    Example:
        intent_validate("R3")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        intent = engine.get_device_intent(device)

        if not intent:
            return json.dumps({
                "status": "no_intent",
                "device": device,
                "message": f"No intent defined for {device}. Add YAML files to data/intents/",
            }, indent=2)

        result = await engine.validate_device(device)

        return json.dumps({
            "status": "success",
            "device": device,
            "role": intent.role,
            "total_violations": len(result.violations),
            "resolved_count": result.resolved_count,
            "critical_count": sum(1 for v in result.violations if v.violation_severity == "critical"),
            "warning_count": sum(1 for v in result.violations if v.violation_severity == "warning"),
            "violations": [v.to_dict() for v in result.violations],
            "intent_summary": {
                "ospf_neighbors": len(intent.ospf_neighbors),
                "bgp_peers": len(intent.bgp_peers),
                "interfaces": len(intent.interfaces),
                "routes": len(intent.routes),
            },
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def intent_validate_all() -> str:
    """
    Validate all devices with defined intents.

    Checks every device that has a YAML intent definition and reports violations.

    Returns:
        JSON with per-device validation results

    Example:
        intent_validate_all()
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        results = await engine.validate_all()

        summary = {}
        total_violations = 0
        total_resolved = 0
        for device, result in results.items():
            total_violations += len(result.violations)
            total_resolved += result.resolved_count
            summary[device] = {
                "total_violations": len(result.violations),
                "resolved_count": result.resolved_count,
                "critical": sum(1 for v in result.violations if v.violation_severity == "critical"),
                "warning": sum(1 for v in result.violations if v.violation_severity == "warning"),
                "violations": [v.to_dict() for v in result.violations],
            }

        return json.dumps({
            "status": "success",
            "devices_checked": len(results),
            "total_violations": total_violations,
            "total_resolved": total_resolved,
            "results": summary,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
        }, indent=2)


async def intent_discover(device: str) -> str:
    """
    Discover intents from a device's current live state.

    Generates YAML intent definitions based on what's currently running.
    Useful for bootstrapping intent files from a known-good state.

    Filters:
    - OSPF: only FULL neighbors
    - BGP: only Established peers
    - Interfaces: only admin up interfaces
    - Routes: excludes connected/local/kernel routes

    Args:
        device: Device name (e.g., "R1", "edge1")

    Returns:
        JSON with discovered intent dict, YAML string, and suggested save path

    Example:
        intent_discover("R1")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        intent_dict = await engine.discover_intents(device)
        yaml_str = engine.discover_intents_yaml(intent_dict)

        return json.dumps({
            "status": "success",
            "device": device,
            "intent": intent_dict,
            "yaml": yaml_str,
            "suggested_path": f"data/intents/overrides/{device}.yaml",
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def intent_resolve(device: str, violation_id: int) -> str:
    """
    Manually resolve an intent violation by ID.

    Args:
        device: Device name (for context/validation)
        violation_id: The violation row ID to resolve

    Returns:
        JSON with success/failure status

    Example:
        intent_resolve("R1", 42)
    """
    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        resolved = engine.resolve_violation(violation_id)

        if resolved:
            return json.dumps({
                "status": "success",
                "message": f"Violation {violation_id} resolved",
            }, indent=2)
        else:
            return json.dumps({
                "status": "not_found",
                "message": f"Violation {violation_id} not found or already resolved",
            }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
        }, indent=2)


async def intent_health(device: Optional[str] = None) -> str:
    """
    Get intent health score for a device or the entire network.

    Uses stored violations from the database — run intent_validate_all()
    first for up-to-date results.

    Args:
        device: Device name, or None for network-wide score

    Returns:
        JSON with health score (0-100), violation counts, per-device breakdown

    Examples:
        intent_health()          # Network-wide
        intent_health("R1")      # Single device
    """
    if device and device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        health = engine.compute_health_score(device=device)

        return json.dumps({
            "status": "success",
            **health,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
        }, indent=2)


async def intent_report() -> str:
    """
    Generate a consolidated network intent compliance report.

    Returns network score, per-device breakdown (failing first),
    top critical violations, and a summary string.

    Uses stored violations — run intent_validate_all() first for
    up-to-date results.

    Returns:
        JSON with full report

    Example:
        intent_report()
    """
    from core.intent_engine import get_intent_engine

    try:
        engine = get_intent_engine()
        report = engine.generate_report()

        return json.dumps({
            "status": "success",
            **report,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
        }, indent=2)


# =============================================================================
# Dependency Graph Tools
# =============================================================================


async def impact_blast_radius(device: str, interface: str) -> str:
    """
    Calculate blast radius of a specific interface going down.

    Uses the dependency graph to trace which devices and services would be
    affected if a particular interface fails.

    Args:
        device: Device name (e.g., "R3")
        interface: Interface name (e.g., "GigabitEthernet4")

    Returns:
        JSON with affected devices and blast radius count

    Example:
        impact_blast_radius("R3", "GigabitEthernet4")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.dependency_graph import NetworkDependencyGraph

    try:
        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            await graph.build()

        result = graph.blast_radius(device, interface)

        return json.dumps({
            "status": "success",
            **result,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
            "interface": interface,
        }, indent=2)


async def impact_forward_analysis(device: str) -> str:
    """
    Analyze what breaks if a device goes down.

    Uses the dependency graph to trace all downstream effects.

    Args:
        device: Device name

    Returns:
        JSON with affected devices, BGP peers lost, OSPF adjacencies lost

    Example:
        impact_forward_analysis("R3")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.dependency_graph import NetworkDependencyGraph

    try:
        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            await graph.build()

        result = graph.forward_impact(device)

        return json.dumps({
            "status": "success",
            **result,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def impact_backward_analysis(device: str) -> str:
    """
    Analyze what must be up for a device to work.

    Uses the dependency graph to trace all upstream dependencies.

    Args:
        device: Device name

    Returns:
        JSON with dependency list

    Example:
        impact_backward_analysis("R3")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.dependency_graph import NetworkDependencyGraph

    try:
        graph = NetworkDependencyGraph()
        if not graph.load_latest():
            await graph.build()

        result = graph.backward_dependencies(device)

        return json.dumps({
            "status": "success",
            **result,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


async def drift_with_impact(device: str) -> str:
    """
    Run drift check with downstream impact tracing.

    Combines baseline drift detection with dependency graph analysis to show
    not just WHAT changed, but WHAT'S AFFECTED by the change.

    Args:
        device: Device name

    Returns:
        JSON with drift report + downstream impact for each impactful drift

    Example:
        drift_with_impact("R3")
    """
    if not is_enabled("impact_analysis_enabled"):
        return json.dumps({
            "status": "disabled",
            "reason": "Impact analysis feature is disabled",
        }, indent=2)

    if device not in DEVICES:
        return json.dumps({
            "status": "error",
            "reason": f"Device '{device}' not found",
        }, indent=2)

    from core.impact_trending import get_impact_trending

    try:
        trending = get_impact_trending()

        baseline = trending.get_baseline(device)
        if baseline is None:
            return json.dumps({
                "status": "no_baseline",
                "device": device,
                "message": f"No baseline set for {device}. Use impact_baseline_set() first.",
            }, indent=2)

        result = await trending.drift_with_impact(device)

        return json.dumps({
            "status": "success",
            **result,
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "reason": str(e),
            "device": device,
        }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    # Impact analysis tools
    {"fn": impact_analyze, "name": "impact_analyze", "category": "impact"},
    {"fn": impact_status, "name": "impact_status", "category": "impact"},
    {"fn": impact_check_interface, "name": "impact_check_interface", "category": "impact"},
    # Trending tools
    {"fn": impact_snapshot, "name": "impact_snapshot", "category": "trending"},
    {"fn": impact_baseline_set, "name": "impact_baseline_set", "category": "trending"},
    {"fn": impact_baseline_get, "name": "impact_baseline_get", "category": "trending"},
    {"fn": impact_drift_check, "name": "impact_drift_check", "category": "trending"},
    {"fn": impact_trending_summary, "name": "impact_trending_summary", "category": "trending"},
    # Intent validation tools
    {"fn": intent_validate, "name": "intent_validate", "category": "intent"},
    {"fn": intent_validate_all, "name": "intent_validate_all", "category": "intent"},
    {"fn": intent_discover, "name": "intent_discover", "category": "intent"},
    {"fn": intent_resolve, "name": "intent_resolve", "category": "intent"},
    {"fn": intent_health, "name": "intent_health", "category": "intent"},
    {"fn": intent_report, "name": "intent_report", "category": "intent"},
    # Dependency graph tools
    {"fn": impact_blast_radius, "name": "impact_blast_radius", "category": "graph"},
    {"fn": impact_forward_analysis, "name": "impact_forward_analysis", "category": "graph"},
    {"fn": impact_backward_analysis, "name": "impact_backward_analysis", "category": "graph"},
    {"fn": drift_with_impact, "name": "drift_with_impact", "category": "drift"},
]
