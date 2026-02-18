"""
Webhook Integration Module for NetworkOps.

Provides robust webhook delivery with:
- Multiple targets: Slack, Teams, Discord, PagerDuty, Generic
- Retry logic with exponential backoff
- Message formatting per platform
- Webhook testing
- Alert templates

Supports async delivery for non-blocking operation.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from core.timestamps import now, isonow
from enum import Enum
from typing import Optional, Any

import aiohttp
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

class WebhookTarget(str, Enum):
    """Supported webhook targets."""
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class WebhookConfig:
    """Webhook configuration from environment."""
    slack_url: Optional[str] = None
    teams_url: Optional[str] = None
    discord_url: Optional[str] = None
    pagerduty_key: Optional[str] = None
    generic_url: Optional[str] = None
    generic_headers: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> 'WebhookConfig':
        """Load configuration from environment variables."""
        from config.vault_client import get_webhook_urls
        wh = get_webhook_urls()

        headers = {}
        generic_auth = os.environ.get("GENERIC_WEBHOOK_AUTH_HEADER")
        generic_value = os.environ.get("GENERIC_WEBHOOK_AUTH_VALUE")
        if generic_auth and generic_value:
            headers[generic_auth] = generic_value

        return cls(
            slack_url=wh.get("slack_url"),
            teams_url=wh.get("teams_url"),
            discord_url=wh.get("discord_url"),
            pagerduty_key=wh.get("pagerduty_key"),
            generic_url=wh.get("generic_url"),
            generic_headers=headers,
        )


# =============================================================================
# Message Formatters
# =============================================================================

def format_slack_message(
    title: str,
    message: str,
    severity: str = "info",
    fields: dict = None,
) -> dict:
    """Format message for Slack Incoming Webhook."""
    severity_colors = {
        "info": "#36a64f",
        "warning": "#ff9800",
        "error": "#ff5722",
        "critical": "#dc3545",
    }

    color = severity_colors.get(severity, "#808080")

    attachment = {
        "color": color,
        "title": title,
        "text": message,
        "footer": "NetworkOps",
        "ts": int(now().timestamp()),
    }

    if fields:
        attachment["fields"] = [
            {"title": k, "value": str(v), "short": len(str(v)) < 30}
            for k, v in fields.items()
        ]

    return {"attachments": [attachment]}


def format_teams_message(
    title: str,
    message: str,
    severity: str = "info",
    fields: dict = None,
) -> dict:
    """Format message for Microsoft Teams Incoming Webhook."""
    severity_colors = {
        "info": "00FF00",
        "warning": "FFA500",
        "error": "FF5722",
        "critical": "FF0000",
    }

    color = severity_colors.get(severity, "808080")

    card = {
        "@type": "MessageCard",
        "themeColor": color,
        "title": title,
        "text": message,
    }

    if fields:
        card["sections"] = [{
            "facts": [
                {"name": k, "value": str(v)}
                for k, v in fields.items()
            ]
        }]

    return card


def format_discord_message(
    title: str,
    message: str,
    severity: str = "info",
    fields: dict = None,
) -> dict:
    """Format message for Discord Webhook."""
    severity_colors = {
        "info": 0x36a64f,
        "warning": 0xff9800,
        "error": 0xff5722,
        "critical": 0xdc3545,
    }

    color = severity_colors.get(severity, 0x808080)

    embed = {
        "title": title,
        "description": message,
        "color": color,
        "timestamp": isonow(),
        "footer": {"text": "NetworkOps"},
    }

    if fields:
        embed["fields"] = [
            {"name": k, "value": str(v), "inline": len(str(v)) < 30}
            for k, v in fields.items()
        ]

    return {"embeds": [embed]}


def format_pagerduty_event(
    title: str,
    message: str,
    severity: str = "info",
    routing_key: str = "",
    dedup_key: str = None,
) -> dict:
    """Format event for PagerDuty Events API v2."""
    severity_map = {
        "info": "info",
        "warning": "warning",
        "error": "error",
        "critical": "critical",
    }

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": title[:1024],
            "severity": severity_map.get(severity, "info"),
            "source": "NetworkOps",
            "custom_details": {"message": message},
        },
    }

    if dedup_key:
        payload["dedup_key"] = dedup_key

    return payload


def format_generic_message(
    title: str,
    message: str,
    severity: str = "info",
    fields: dict = None,
) -> dict:
    """Format message for generic webhook endpoint."""
    return {
        "title": title,
        "message": message,
        "severity": severity,
        "timestamp": isonow(),
        "source": "NetworkOps",
        "fields": fields or {},
    }


# =============================================================================
# Webhook Delivery
# =============================================================================

class WebhookDeliveryError(Exception):
    """Webhook delivery failed."""
    pass


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(aiohttp.ClientError),
)
async def _send_webhook(
    url: str,
    payload: dict,
    headers: dict = None,
) -> dict:
    """
    Send webhook with retry logic.

    Retries up to 3 times with exponential backoff on transient errors.
    """
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            json=payload,
            headers=default_headers,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            response_text = await resp.text()

            if resp.status in (200, 201, 202, 204):
                return {
                    "success": True,
                    "status_code": resp.status,
                    "response": response_text[:500],
                }
            else:
                raise WebhookDeliveryError(
                    f"Webhook returned {resp.status}: {response_text[:200]}"
                )


async def send_to_slack(
    message: str,
    title: str = None,
    severity: str = "info",
    fields: dict = None,
    url: str = None,
) -> dict:
    """Send alert to Slack."""
    webhook_url = url or os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return {"success": False, "error": "SLACK_WEBHOOK_URL not configured"}

    title = title or f"NetworkOps Alert ({severity.upper()})"
    payload = format_slack_message(title, message, severity, fields)

    try:
        return await _send_webhook(webhook_url, payload)
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_to_teams(
    message: str,
    title: str = None,
    severity: str = "info",
    fields: dict = None,
    url: str = None,
) -> dict:
    """Send alert to Microsoft Teams."""
    webhook_url = url or os.environ.get("TEAMS_WEBHOOK_URL")
    if not webhook_url:
        return {"success": False, "error": "TEAMS_WEBHOOK_URL not configured"}

    title = title or f"NetworkOps Alert ({severity.upper()})"
    payload = format_teams_message(title, message, severity, fields)

    try:
        return await _send_webhook(webhook_url, payload)
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_to_discord(
    message: str,
    title: str = None,
    severity: str = "info",
    fields: dict = None,
    url: str = None,
) -> dict:
    """Send alert to Discord."""
    webhook_url = url or os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        return {"success": False, "error": "DISCORD_WEBHOOK_URL not configured"}

    title = title or f"NetworkOps Alert ({severity.upper()})"
    payload = format_discord_message(title, message, severity, fields)

    try:
        return await _send_webhook(webhook_url, payload)
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_to_pagerduty(
    message: str,
    title: str = None,
    severity: str = "info",
    dedup_key: str = None,
    routing_key: str = None,
) -> dict:
    """Send event to PagerDuty."""
    key = routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY")
    if not key:
        return {"success": False, "error": "PAGERDUTY_ROUTING_KEY not configured"}

    title = title or message[:1024]
    payload = format_pagerduty_event(title, message, severity, key, dedup_key)

    try:
        return await _send_webhook(
            "https://events.pagerduty.com/v2/enqueue",
            payload
        )
    except Exception as e:
        return {"success": False, "error": str(e)}


async def send_to_generic(
    message: str,
    title: str = None,
    severity: str = "info",
    fields: dict = None,
    url: str = None,
    headers: dict = None,
) -> dict:
    """Send alert to generic webhook endpoint."""
    webhook_url = url or os.environ.get("GENERIC_WEBHOOK_URL")
    if not webhook_url:
        return {"success": False, "error": "GENERIC_WEBHOOK_URL not configured"}

    title = title or f"NetworkOps Alert ({severity.upper()})"
    payload = format_generic_message(title, message, severity, fields)

    # Get auth headers from env if not provided
    if headers is None:
        headers = {}
        auth_header = os.environ.get("GENERIC_WEBHOOK_AUTH_HEADER")
        auth_value = os.environ.get("GENERIC_WEBHOOK_AUTH_VALUE")
        if auth_header and auth_value:
            headers[auth_header] = auth_value

    try:
        return await _send_webhook(webhook_url, payload, headers)
    except Exception as e:
        return {"success": False, "error": str(e)}


# =============================================================================
# Multi-Target Delivery
# =============================================================================

async def send_alert(
    message: str,
    title: str = None,
    severity: str = "info",
    targets: list[str] = None,
    fields: dict = None,
) -> dict:
    """
    Send alert to multiple webhook targets.

    Args:
        message: Alert message
        title: Optional alert title
        severity: info, warning, error, critical
        targets: List of targets (slack, teams, discord, pagerduty, generic)
                 If None, uses all configured targets
        fields: Additional key-value fields to include

    Returns:
        Dict with results per target
    """
    config = WebhookConfig.from_env()

    # Determine which targets to use
    if targets is None:
        targets = []
        if config.slack_url:
            targets.append("slack")
        if config.teams_url:
            targets.append("teams")
        if config.discord_url:
            targets.append("discord")
        if config.pagerduty_key and severity in ("error", "critical"):
            targets.append("pagerduty")
        if config.generic_url:
            targets.append("generic")

    if not targets:
        return {
            "success": False,
            "error": "No webhook targets configured",
            "results": []
        }

    # Send to all targets in parallel
    tasks = []
    for target in targets:
        if target == "slack":
            tasks.append(("slack", send_to_slack(message, title, severity, fields)))
        elif target == "teams":
            tasks.append(("teams", send_to_teams(message, title, severity, fields)))
        elif target == "discord":
            tasks.append(("discord", send_to_discord(message, title, severity, fields)))
        elif target == "pagerduty":
            tasks.append(("pagerduty", send_to_pagerduty(message, title, severity)))
        elif target == "generic":
            tasks.append(("generic", send_to_generic(message, title, severity, fields)))

    # Execute all
    results = []
    for target_name, coro in tasks:
        try:
            result = await coro
            result["target"] = target_name
            results.append(result)
        except Exception as e:
            results.append({"target": target_name, "success": False, "error": str(e)})

    success_count = sum(1 for r in results if r.get("success"))

    return {
        "success": success_count > 0,
        "sent": success_count,
        "failed": len(results) - success_count,
        "results": results,
    }


# =============================================================================
# Webhook Testing
# =============================================================================

async def test_webhook(target: str, url: str = None) -> dict:
    """
    Test a webhook by sending a test message.

    Args:
        target: slack, teams, discord, pagerduty, or generic
        url: Optional override URL (uses env var if not provided)

    Returns:
        Test result with success status
    """
    test_message = "🔧 This is a test message from NetworkOps"
    test_title = "Webhook Test"
    test_fields = {
        "Test Type": "Connectivity",
        "Timestamp": isonow(),
    }

    if target == "slack":
        return await send_to_slack(test_message, test_title, "info", test_fields, url)
    elif target == "teams":
        return await send_to_teams(test_message, test_title, "info", test_fields, url)
    elif target == "discord":
        return await send_to_discord(test_message, test_title, "info", test_fields, url)
    elif target == "pagerduty":
        # PagerDuty test with dedup_key to avoid actual alert
        return await send_to_pagerduty(
            test_message, test_title, "info",
            dedup_key="networkops-test-" + now().strftime("%Y%m%d")
        )
    elif target == "generic":
        return await send_to_generic(test_message, test_title, "info", test_fields, url)
    else:
        return {"success": False, "error": f"Unknown target: {target}"}


async def get_configured_webhooks() -> dict:
    """Get list of configured webhook targets."""
    config = WebhookConfig.from_env()

    webhooks = []
    if config.slack_url:
        webhooks.append({"target": "slack", "configured": True, "url_set": True})
    if config.teams_url:
        webhooks.append({"target": "teams", "configured": True, "url_set": True})
    if config.discord_url:
        webhooks.append({"target": "discord", "configured": True, "url_set": True})
    if config.pagerduty_key:
        webhooks.append({"target": "pagerduty", "configured": True, "key_set": True})
    if config.generic_url:
        webhooks.append({"target": "generic", "configured": True, "url_set": True})

    return {
        "configured_count": len(webhooks),
        "webhooks": webhooks,
        "env_vars": {
            "SLACK_WEBHOOK_URL": bool(config.slack_url),
            "TEAMS_WEBHOOK_URL": bool(config.teams_url),
            "DISCORD_WEBHOOK_URL": bool(config.discord_url),
            "PAGERDUTY_ROUTING_KEY": bool(config.pagerduty_key),
            "GENERIC_WEBHOOK_URL": bool(config.generic_url),
        }
    }


# =============================================================================
# Alert Templates
# =============================================================================

async def send_device_down_alert(
    device_name: str,
    device_ip: str,
    error: str = None,
    targets: list[str] = None,
) -> dict:
    """Send device down alert."""
    return await send_alert(
        message=f"Device {device_name} ({device_ip}) is unreachable.\n{error or ''}",
        title=f"🔴 Device Down: {device_name}",
        severity="critical",
        targets=targets,
        fields={
            "Device": device_name,
            "IP": device_ip,
            "Status": "DOWN",
        }
    )


async def send_device_recovered_alert(
    device_name: str,
    device_ip: str,
    targets: list[str] = None,
) -> dict:
    """Send device recovered alert."""
    return await send_alert(
        message=f"Device {device_name} ({device_ip}) is back online.",
        title=f"🟢 Device Recovered: {device_name}",
        severity="info",
        targets=targets,
        fields={
            "Device": device_name,
            "IP": device_ip,
            "Status": "UP",
        }
    )


async def send_interface_down_alert(
    device_name: str,
    interface: str,
    targets: list[str] = None,
) -> dict:
    """Send interface down alert."""
    return await send_alert(
        message=f"Interface {interface} on {device_name} is down.",
        title=f"⚠️ Interface Down: {device_name} {interface}",
        severity="warning",
        targets=targets,
        fields={
            "Device": device_name,
            "Interface": interface,
            "Status": "DOWN",
        }
    )


async def send_config_change_alert(
    device_name: str,
    user: str,
    change_summary: str,
    targets: list[str] = None,
) -> dict:
    """Send configuration change alert."""
    return await send_alert(
        message=f"Configuration change on {device_name} by {user}.\n{change_summary}",
        title=f"📝 Config Change: {device_name}",
        severity="info",
        targets=targets,
        fields={
            "Device": device_name,
            "User": user,
            "Change": change_summary[:100],
        }
    )


async def send_backup_complete_alert(
    device_count: int,
    success_count: int,
    targets: list[str] = None,
) -> dict:
    """Send backup completion alert."""
    severity = "info" if success_count == device_count else "warning"
    return await send_alert(
        message=f"Configuration backup completed: {success_count}/{device_count} successful.",
        title=f"💾 Backup Complete",
        severity=severity,
        targets=targets,
        fields={
            "Total Devices": device_count,
            "Successful": success_count,
            "Failed": device_count - success_count,
        }
    )
