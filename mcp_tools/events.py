"""
Event Correlation MCP tools.

This module provides tools for event logging and correlation:
- get_event_log: Get recent audit events
- clear_event_log: Clear audit log
- event_collect: Collect live events from device
- event_correlate: Run correlation analysis
- event_incidents: Get incidents with filters
- event_incident_detail: Get incident details
- event_rca: Root cause analysis
- event_update_status: Update incident status
- event_stats: Get event statistics
"""

import json

from core import log_event, event_logger


# =============================================================================
# Event Log MCP Tool Functions
# =============================================================================

def get_event_log(limit: int = 50, device: str = None, action: str = None) -> str:
    """
    Get recent events from the audit log.

    Args:
        limit: Number of events to return (default 50, max 500)
        device: Filter by device name (optional)
        action: Filter by action type (optional)
    """
    from core.event_logger import MAX_EVENTS

    limit = min(limit, MAX_EVENTS)
    events = event_logger.get_events(limit=limit, device=device, action=action)

    return json.dumps({
        "total_events": len(event_logger.events),
        "returned": len(events),
        "filters": {"device": device, "action": action},
        "events": events
    }, indent=2)


def clear_event_log() -> str:
    """Clear all events from the audit log"""
    from core import clear_event_log as core_clear

    count = len(event_logger.events)
    core_clear()

    log_event("log_cleared", details=f"Cleared {count} events", role="admin")

    return json.dumps({
        "status": "success",
        "cleared_count": count,
    }, indent=2)


# =============================================================================
# Event Correlation MCP Tool Functions
# =============================================================================

async def event_collect(device: str) -> str:
    """
    Collect live events from a device by checking its current state.

    Checks interface status, OSPF neighbors, and BGP peers for issues.

    Args:
        device: Device name (e.g., "R1")

    Returns:
        JSON with collected events
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        events = await correlator.collect_live_events(device)

        # Add events to correlator
        added = 0
        for event in events:
            if correlator.add_event(event):
                added += 1

        return json.dumps({
            "device": device,
            "events_found": len(events),
            "events_added": added,
            "events_suppressed": len(events) - added,
            "events": [e.to_dict() for e in events],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


async def event_correlate() -> str:
    """
    Run correlation analysis on uncorrelated events.

    Groups related events into incidents and identifies root causes.

    Returns:
        JSON with new incidents created from correlation
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        incidents = correlator.correlate()

        return json.dumps({
            "incidents_created": len(incidents),
            "incidents": [i.to_dict() for i in incidents],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def event_incidents(
    status: str = None,
    severity: str = None,
    device: str = None,
    hours: int = 24,
) -> str:
    """
    Get incidents with optional filters.

    Args:
        status: Filter by status: open, acknowledged, investigating, resolved
        severity: Filter by severity: critical, high, medium, low
        device: Filter by affected device
        hours: Look back period (default: 24)

    Returns:
        JSON with matching incidents
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        incidents = correlator.get_incidents(status, severity, device, hours)

        return json.dumps({
            "filters": {
                "status": status,
                "severity": severity,
                "device": device,
                "hours": hours,
            },
            "count": len(incidents),
            "incidents": [i.to_dict() for i in incidents],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def event_incident_detail(incident_id: str) -> str:
    """
    Get detailed information about an incident.

    Args:
        incident_id: Incident ID to look up

    Returns:
        JSON with incident details, timeline, and events
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        incident = correlator.get_incident(incident_id)

        if not incident:
            return json.dumps({
                "error": f"Incident {incident_id} not found"
            }, indent=2)

        events = correlator.get_events_for_incident(incident_id)

        return json.dumps({
            "incident": incident.to_dict(),
            "events": [e.to_dict() for e in events],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def event_rca(incident_id: str) -> str:
    """
    Perform root cause analysis for an incident.

    Provides detailed analysis including:
    - Root cause identification
    - Event timeline
    - Impact assessment
    - Remediation recommendations

    Args:
        incident_id: Incident ID to analyze

    Returns:
        JSON with comprehensive RCA report
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        rca = correlator.analyze_root_cause(incident_id)

        return json.dumps(rca, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def event_update_status(incident_id: str, status: str) -> str:
    """
    Update the status of an incident.

    Args:
        incident_id: Incident ID to update
        status: New status: open, acknowledged, investigating, resolved

    Returns:
        JSON with updated incident
    """
    from core.event_correlation import get_event_correlator, IncidentStatus

    valid_statuses = ["open", "acknowledged", "investigating", "resolved"]
    if status not in valid_statuses:
        return json.dumps({
            "error": f"Invalid status. Must be one of: {valid_statuses}"
        }, indent=2)

    try:
        correlator = get_event_correlator()
        incident = correlator.update_incident_status(
            incident_id,
            IncidentStatus(status),
        )

        if not incident:
            return json.dumps({
                "error": f"Incident {incident_id} not found"
            }, indent=2)

        return json.dumps({
            "updated": True,
            "incident": incident.to_dict(),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def event_stats(hours: int = 24) -> str:
    """
    Get event statistics and summary.

    Args:
        hours: Look back period (default: 24)

    Returns:
        JSON with event counts by type, severity, device
    """
    from core.event_correlation import get_event_correlator

    try:
        correlator = get_event_correlator()
        stats = correlator.get_event_stats(hours)

        return json.dumps(stats, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    # Event log tools (2)
    {"fn": get_event_log, "name": "get_event_log", "category": "events"},
    {"fn": clear_event_log, "name": "clear_event_log", "category": "events"},
    # Event correlation tools (7)
    {"fn": event_collect, "name": "event_collect", "category": "events"},
    {"fn": event_correlate, "name": "event_correlate", "category": "events"},
    {"fn": event_incidents, "name": "event_incidents", "category": "events"},
    {"fn": event_incident_detail, "name": "event_incident_detail", "category": "events"},
    {"fn": event_rca, "name": "event_rca", "category": "events"},
    {"fn": event_update_status, "name": "event_update_status", "category": "events"},
    {"fn": event_stats, "name": "event_stats", "category": "events"},
]
