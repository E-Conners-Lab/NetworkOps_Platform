"""
Notifications MCP tools.

This module provides tools for webhook notifications and syslog:
- webhook_send: Send alert to webhook targets
- webhook_test: Test a webhook
- webhook_list: List configured webhooks
- webhook_alert_device_down: Send device down alert
- webhook_alert_device_recovered: Send device recovered alert
- webhook_alert_interface_down: Send interface down alert
- syslog_start: Start syslog receiver
- syslog_stop: Stop syslog receiver
- syslog_status: Get syslog receiver status
- syslog_events: Get filtered syslog events
- syslog_summary: Get syslog summary by device
- syslog_clear: Clear syslog buffer
- syslog_severity_levels: Get severity level reference
- send_notification: Send to Slack/Teams/PagerDuty
- create_ticket: Create ServiceNow/Jira tickets
"""

import json
import os
from core.timestamps import isonow, now

import aiohttp

from core import log_event
from core.webhooks import (
    send_alert,
    test_webhook,
    get_configured_webhooks,
    send_device_down_alert,
    send_device_recovered_alert,
    send_interface_down_alert,
)
from core.syslog_receiver import (
    start_receiver as start_syslog_receiver,
    stop_receiver as stop_syslog_receiver,
    get_syslog_events,
    get_syslog_stats,
    get_syslog_summary,
    clear_syslog_events,
    SEVERITY_NAMES,
    FACILITY_NAMES,
)


# =============================================================================
# Webhook Tools
# =============================================================================

async def webhook_send(
    message: str,
    title: str = None,
    severity: str = "info",
    targets: str = None,
) -> str:
    """
    Send alert to webhook targets (Slack, Teams, Discord, PagerDuty).

    Args:
        message: Alert message content
        title: Optional alert title
        severity: info, warning, error, critical (default: info)
        targets: Comma-separated targets (slack,teams,discord,pagerduty,generic)
                 If not specified, sends to all configured targets

    Returns:
        JSON with delivery results per target

    Examples:
        # Send to all configured webhooks
        webhook_send("R1 is unreachable", "Device Alert", "critical")

        # Send only to Slack and Teams
        webhook_send("Backup completed", targets="slack,teams")
    """
    target_list = None
    if targets:
        target_list = [t.strip() for t in targets.split(",")]

    result = await send_alert(
        message=message,
        title=title,
        severity=severity,
        targets=target_list,
    )
    return json.dumps(result, indent=2)


async def webhook_test(target: str, url: str = None) -> str:
    """
    Test a webhook by sending a test message.

    Args:
        target: Webhook target to test (slack, teams, discord, pagerduty, generic)
        url: Optional override URL (uses env var if not provided)

    Returns:
        JSON with test result (success/failure)
    """
    result = await test_webhook(target, url)
    return json.dumps(result, indent=2)


async def webhook_list() -> str:
    """
    List configured webhook targets.

    Returns:
        JSON with configured webhooks and their status
    """
    result = await get_configured_webhooks()
    return json.dumps(result, indent=2)


async def webhook_alert_device_down(
    device_name: str,
    device_ip: str,
    error: str = None,
    targets: str = None,
) -> str:
    """
    Send device down alert to all configured webhooks.

    Args:
        device_name: Name of the down device
        device_ip: IP address of the device
        error: Optional error message
        targets: Comma-separated targets (optional)

    Returns:
        JSON with delivery results
    """
    target_list = [t.strip() for t in targets.split(",")] if targets else None
    result = await send_device_down_alert(device_name, device_ip, error, target_list)
    return json.dumps(result, indent=2)


async def webhook_alert_device_recovered(
    device_name: str,
    device_ip: str,
    targets: str = None,
) -> str:
    """
    Send device recovered alert to all configured webhooks.

    Args:
        device_name: Name of the recovered device
        device_ip: IP address of the device
        targets: Comma-separated targets (optional)

    Returns:
        JSON with delivery results
    """
    target_list = [t.strip() for t in targets.split(",")] if targets else None
    result = await send_device_recovered_alert(device_name, device_ip, target_list)
    return json.dumps(result, indent=2)


async def webhook_alert_interface_down(
    device_name: str,
    interface: str,
    targets: str = None,
) -> str:
    """
    Send interface down alert to all configured webhooks.

    Args:
        device_name: Name of the device
        interface: Interface name (e.g., GigabitEthernet1)
        targets: Comma-separated targets (optional)

    Returns:
        JSON with delivery results
    """
    target_list = [t.strip() for t in targets.split(",")] if targets else None
    result = await send_interface_down_alert(device_name, interface, target_list)
    return json.dumps(result, indent=2)


# =============================================================================
# Syslog Tools
# =============================================================================

async def syslog_start() -> str:
    """
    Start the syslog receiver to collect events from network devices.

    Listens on UDP port 1514 (or SYSLOG_PORT env var) for syslog messages.
    Configure devices to send syslog to this server's IP on the configured port.

    Returns:
        JSON with receiver status
    """
    success = await start_syslog_receiver()
    if success:
        stats = await get_syslog_stats()
        return json.dumps({
            "success": True,
            "message": f"Syslog receiver started on UDP port {stats['port']}",
            "stats": stats
        }, indent=2)
    else:
        return json.dumps({
            "success": False,
            "error": "Failed to start syslog receiver (port may be in use)"
        }, indent=2)


async def syslog_stop() -> str:
    """
    Stop the syslog receiver.

    Returns:
        JSON with stop status
    """
    await stop_syslog_receiver()
    return json.dumps({
        "success": True,
        "message": "Syslog receiver stopped"
    }, indent=2)


async def syslog_status() -> str:
    """
    Get syslog receiver status and statistics.

    Returns:
        JSON with receiver status, port, buffer size, and message counts
    """
    stats = await get_syslog_stats()
    return json.dumps(stats, indent=2)


async def syslog_events(
    device: str = None,
    severity: str = None,
    min_severity: int = None,
    facility: str = None,
    search: str = None,
    limit: int = 100,
) -> str:
    """
    Get filtered syslog events from the receiver buffer.

    Args:
        device: Filter by device name (e.g., "R1")
        severity: Filter by exact severity (emergency, alert, critical, error,
                  warning, notice, info, debug)
        min_severity: Filter by minimum severity level (0=emergency to 7=debug)
                      e.g., 3 = error and higher (error, critical, alert, emergency)
        facility: Filter by facility name (e.g., "local7", "auth")
        search: Search text in message content
        limit: Maximum events to return (default: 100)

    Returns:
        JSON with filtered events (newest first)

    Examples:
        # Get all errors and critical from R1
        syslog_events(device="R1", min_severity=3)

        # Search for interface-related messages
        syslog_events(search="interface", limit=50)

        # Get auth-related events
        syslog_events(facility="auth")
    """
    events = await get_syslog_events(
        device=device,
        severity=severity,
        min_severity=min_severity,
        facility=facility,
        search=search,
        limit=limit,
    )

    return json.dumps({
        "count": len(events),
        "events": events
    }, indent=2)


async def syslog_summary() -> str:
    """
    Get syslog event summary by device.

    Shows event counts per device, broken down by severity.

    Returns:
        JSON with device-level event summary
    """
    summary = await get_syslog_summary()
    return json.dumps({
        "devices": summary,
        "device_count": len(summary),
    }, indent=2)


async def syslog_clear() -> str:
    """
    Clear all events from the syslog buffer.

    Returns:
        JSON with count of cleared events
    """
    count = await clear_syslog_events()
    return json.dumps({
        "success": True,
        "message": f"Cleared {count} events from buffer"
    }, indent=2)


async def syslog_severity_levels() -> str:
    """
    Get list of syslog severity levels and facility codes.

    Useful for filtering events by severity or facility.

    Returns:
        JSON with severity and facility reference
    """
    return json.dumps({
        "severities": [
            {"level": k, "name": v, "description": {
                0: "System is unusable",
                1: "Action must be taken immediately",
                2: "Critical conditions",
                3: "Error conditions",
                4: "Warning conditions",
                5: "Normal but significant condition",
                6: "Informational messages",
                7: "Debug-level messages",
            }.get(k, "")}
            for k, v in SEVERITY_NAMES.items()
        ],
        "facilities": [
            {"code": k, "name": v}
            for k, v in FACILITY_NAMES.items()
        ],
    }, indent=2)


# =============================================================================
# Integration Tools (External Systems)
# =============================================================================

async def send_notification(
    message: str,
    channel: str = "default",
    severity: str = "info",
    title: str = None
) -> str:
    """
    Send notification to Slack, Teams, or PagerDuty.

    Requires webhook URLs configured in environment variables:
    - SLACK_WEBHOOK_URL
    - TEAMS_WEBHOOK_URL
    - PAGERDUTY_ROUTING_KEY

    Args:
        message: Notification message
        channel: "slack", "teams", "pagerduty", or "default" (uses first available)
        severity: "info", "warning", "critical" (affects formatting/routing)
        title: Optional title for the notification

    Returns:
        JSON with send status
    """
    slack_url = os.environ.get("SLACK_WEBHOOK_URL")
    teams_url = os.environ.get("TEAMS_WEBHOOK_URL")
    pagerduty_key = os.environ.get("PAGERDUTY_ROUTING_KEY")

    result = {
        "status": "success",
        "message": message,
        "severity": severity,
        "notifications_sent": []
    }

    # Determine which channels to use
    channels_to_send = []
    if channel == "default":
        if slack_url:
            channels_to_send.append("slack")
        elif teams_url:
            channels_to_send.append("teams")
        elif pagerduty_key and severity == "critical":
            channels_to_send.append("pagerduty")
    else:
        channels_to_send.append(channel)

    if not channels_to_send:
        return json.dumps({
            "status": "error",
            "error": "No notification channels configured. Set SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL, or PAGERDUTY_ROUTING_KEY"
        }, indent=2)

    async with aiohttp.ClientSession() as session:
        for ch in channels_to_send:
            try:
                if ch == "slack" and slack_url:
                    # Slack message format
                    color = "#36a64f" if severity == "info" else "#ff9800" if severity == "warning" else "#dc3545"
                    payload = {
                        "attachments": [{
                            "color": color,
                            "title": title or f"NetworkOps Alert ({severity.upper()})",
                            "text": message,
                            "footer": "NetworkOps MCP",
                            "ts": int(now().timestamp())
                        }]
                    }
                    async with session.post(slack_url, json=payload) as resp:
                        if resp.status == 200:
                            result["notifications_sent"].append({"channel": "slack", "status": "sent"})
                        else:
                            result["notifications_sent"].append({"channel": "slack", "status": "failed", "code": resp.status})

                elif ch == "teams" and teams_url:
                    # Teams message format
                    color = "00FF00" if severity == "info" else "FFA500" if severity == "warning" else "FF0000"
                    payload = {
                        "@type": "MessageCard",
                        "themeColor": color,
                        "title": title or f"NetworkOps Alert ({severity.upper()})",
                        "text": message
                    }
                    async with session.post(teams_url, json=payload) as resp:
                        if resp.status == 200:
                            result["notifications_sent"].append({"channel": "teams", "status": "sent"})
                        else:
                            result["notifications_sent"].append({"channel": "teams", "status": "failed", "code": resp.status})

                elif ch == "pagerduty" and pagerduty_key:
                    # PagerDuty Events API v2
                    pd_severity = "critical" if severity == "critical" else "warning" if severity == "warning" else "info"
                    payload = {
                        "routing_key": pagerduty_key,
                        "event_action": "trigger",
                        "payload": {
                            "summary": title or message[:1024],
                            "severity": pd_severity,
                            "source": "NetworkOps MCP",
                            "custom_details": {"message": message}
                        }
                    }
                    async with session.post("https://events.pagerduty.com/v2/enqueue", json=payload) as resp:
                        if resp.status == 202:
                            result["notifications_sent"].append({"channel": "pagerduty", "status": "sent"})
                        else:
                            result["notifications_sent"].append({"channel": "pagerduty", "status": "failed", "code": resp.status})

            except Exception as e:
                result["notifications_sent"].append({"channel": ch, "status": "error", "error": str(e)})

    if not result["notifications_sent"]:
        result["status"] = "error"
        result["error"] = "No notifications were sent"

    return json.dumps(result, indent=2)


async def create_ticket(
    title: str,
    description: str,
    priority: str = "medium",
    ticket_type: str = "incident",
    assignee: str = None
) -> str:
    """
    Create a ticket in ServiceNow or Jira via webhook.

    Requires webhook URL configured in environment:
    - SERVICENOW_WEBHOOK_URL or JIRA_WEBHOOK_URL

    Args:
        title: Ticket title/summary
        description: Detailed description
        priority: "low", "medium", "high", "critical"
        ticket_type: "incident", "problem", "change", "task"
        assignee: Optional assignee username

    Returns:
        JSON with ticket creation status
    """
    snow_url = os.environ.get("SERVICENOW_WEBHOOK_URL")
    jira_url = os.environ.get("JIRA_WEBHOOK_URL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_project = os.environ.get("JIRA_PROJECT", "OPS")

    if not snow_url and not jira_url:
        return json.dumps({
            "status": "error",
            "error": "No ticket system configured. Set SERVICENOW_WEBHOOK_URL or JIRA_WEBHOOK_URL"
        }, indent=2)

    result = {
        "status": "success",
        "title": title,
        "priority": priority,
        "ticket_type": ticket_type,
        "created_at": isonow()
    }

    async with aiohttp.ClientSession() as session:
        try:
            if jira_url and jira_token:
                # Jira REST API
                priority_map = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Highest"}
                type_map = {"incident": "Bug", "problem": "Bug", "change": "Story", "task": "Task"}

                payload = {
                    "fields": {
                        "project": {"key": jira_project},
                        "summary": title,
                        "description": description,
                        "issuetype": {"name": type_map.get(ticket_type, "Task")},
                        "priority": {"name": priority_map.get(priority, "Medium")}
                    }
                }

                if assignee:
                    payload["fields"]["assignee"] = {"name": assignee}

                auth = aiohttp.BasicAuth(jira_email, jira_token)
                headers = {"Content-Type": "application/json"}

                async with session.post(f"{jira_url}/rest/api/2/issue", json=payload, auth=auth, headers=headers) as resp:
                    if resp.status in [200, 201]:
                        data = await resp.json()
                        result["ticket_id"] = data.get("key")
                        result["ticket_url"] = f"{jira_url}/browse/{data.get('key')}"
                        result["system"] = "jira"
                    else:
                        error_text = await resp.text()
                        result["status"] = "error"
                        result["error"] = f"Jira API error: {resp.status} - {error_text}"

            elif snow_url:
                # ServiceNow webhook (simplified)
                priority_map = {"low": "4", "medium": "3", "high": "2", "critical": "1"}

                payload = {
                    "short_description": title,
                    "description": description,
                    "priority": priority_map.get(priority, "3"),
                    "category": ticket_type,
                    "assignment_group": assignee or "Network Operations"
                }

                async with session.post(snow_url, json=payload) as resp:
                    if resp.status in [200, 201]:
                        data = await resp.json()
                        result["ticket_id"] = data.get("sys_id") or data.get("number")
                        result["system"] = "servicenow"
                    else:
                        result["status"] = "error"
                        result["error"] = f"ServiceNow error: {resp.status}"

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

    log_event("create_ticket", "system", f"Created {ticket_type}: {title}", result["status"], "operator")

    return json.dumps(result, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": webhook_send, "name": "webhook_send", "category": "notifications"},
    {"fn": webhook_test, "name": "webhook_test", "category": "notifications"},
    {"fn": webhook_list, "name": "webhook_list", "category": "notifications"},
    {"fn": webhook_alert_device_down, "name": "webhook_alert_device_down", "category": "notifications"},
    {"fn": webhook_alert_device_recovered, "name": "webhook_alert_device_recovered", "category": "notifications"},
    {"fn": webhook_alert_interface_down, "name": "webhook_alert_interface_down", "category": "notifications"},
    {"fn": syslog_start, "name": "syslog_start", "category": "notifications"},
    {"fn": syslog_stop, "name": "syslog_stop", "category": "notifications"},
    {"fn": syslog_status, "name": "syslog_status", "category": "notifications"},
    {"fn": syslog_events, "name": "syslog_events", "category": "notifications"},
    {"fn": syslog_summary, "name": "syslog_summary", "category": "notifications"},
    {"fn": syslog_clear, "name": "syslog_clear", "category": "notifications"},
    {"fn": syslog_severity_levels, "name": "syslog_severity_levels", "category": "notifications"},
    {"fn": send_notification, "name": "send_notification", "category": "notifications"},
    {"fn": create_ticket, "name": "create_ticket", "category": "notifications"},
]
