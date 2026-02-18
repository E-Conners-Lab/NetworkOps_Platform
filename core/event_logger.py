"""
Centralized event logging for audit trail.

Consolidates event log functionality previously duplicated in:
- network_mcp_async.py
- dashboard/api_server.py
- legacy/network_mcp.py

Usage:
    from core import log_event, get_event_log

    # Log an event
    log_event("send_command", device="R1", details="show ip route", status="success")

    # Get all events
    events = get_event_log()

    # With memory integration (MCP server)
    from core.event_logger import event_logger
    event_logger.set_memory_callback(my_async_callback)
"""

import asyncio
import json
import os
import re
from collections import deque
from core.timestamps import isonow
from pathlib import Path
from typing import Callable, Optional, Awaitable, Any

# Constants
MAX_EVENTS = 500
EVENT_LOG_FILE = Path(__file__).parent.parent / "data" / "event_log.json"

# =============================================================================
# Log Redaction (OWASP A02:2021 - Cryptographic Failures / Sensitive Data)
# =============================================================================

# Feature flag (default: enabled)
ENABLE_LOG_REDACTION = os.getenv("ENABLE_LOG_REDACTION", "true").lower() == "true"
MAX_REDACTION_LENGTH = 10240  # Skip redaction on strings > 10KB (performance)

# Pre-compiled patterns for performance (order matters - more specific first)
REDACTION_PATTERNS = [
    # Explicit key=value patterns
    (re.compile(r'\b(password|passwd|pwd)\s*[=:]\s*\S+', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'\b(secret|api[_-]?key|auth[_-]?token)\s*[=:]\s*\S+', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'\b(private[_-]?key|access[_-]?key)\s*[=:]\s*\S+', re.IGNORECASE), r'\1=***REDACTED***'),

    # Bearer tokens
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-_\.]{20,}', re.IGNORECASE), r'\1***REDACTED***'),

    # JSON-style "key": "value"
    (re.compile(r'(["\'](?:password|secret|token|key)["\'])\s*:\s*["\'][^"\']+["\']', re.IGNORECASE), r'\1: "***REDACTED***"'),

    # Cisco enable/secret patterns in command output
    (re.compile(r'(enable\s+(?:secret|password)\s+\d+\s+)\S+', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(username\s+\S+\s+(?:secret|password)\s+\d+\s+)\S+', re.IGNORECASE), r'\1***REDACTED***'),
]


def _redact_sensitive(text: str) -> str:
    """
    Remove sensitive data from log text.

    Returns original text if:
    - ENABLE_LOG_REDACTION is false
    - Text is None or empty
    - Text exceeds MAX_REDACTION_LENGTH (performance guard)
    """
    if not ENABLE_LOG_REDACTION or not text:
        return text
    if len(text) > MAX_REDACTION_LENGTH:
        return text  # Skip very large strings for performance

    result = text
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class EventLogger:
    """
    Thread-safe event logger with optional async memory integration.

    This class provides a singleton-style interface for event logging,
    with support for pluggable async callbacks (e.g., memory system integration).
    """

    def __init__(
        self,
        log_file: Optional[Path] = None,
        max_events: int = MAX_EVENTS,
    ):
        self._log_file = log_file or EVENT_LOG_FILE
        self._max_events = max_events
        self._event_log: deque = deque(maxlen=max_events)
        self._memory_callback: Optional[Callable[..., Awaitable[Any]]] = None
        self._loaded = False

    def load(self) -> None:
        """Load event log from file."""
        if self._loaded:
            return

        if self._log_file.exists():
            try:
                with open(self._log_file, "r") as f:
                    events = json.load(f)
                    self._event_log = deque(events[-self._max_events:], maxlen=self._max_events)
            except Exception:
                self._event_log = deque(maxlen=self._max_events)

        self._loaded = True

    def save(self) -> None:
        """Save event log to file."""
        try:
            # Ensure data directory exists
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_file, "w") as f:
                json.dump(list(self._event_log), f, indent=2)
        except Exception as e:
            print(f"Failed to save event log: {e}")

    def log(
        self,
        action: str,
        device: Optional[str] = None,
        details: Optional[str] = None,
        status: str = "success",
        role: str = "system",
        user: Optional[str] = None,
    ) -> dict:
        """
        Log an event to the audit trail.

        Args:
            action: The action being logged (e.g., "send_command", "health_check")
            device: The device involved (e.g., "R1", "Switch-R1")
            details: Additional details about the action
            status: Status of the action ("success", "error", "warning")
            role: Role performing the action ("system", "admin", "operator")
            user: Username of the authenticated user (optional)

        Returns:
            The event dict that was logged
        """
        # Ensure log is loaded
        if not self._loaded:
            self.load()

        # Redact sensitive data from details (OWASP A02:2021)
        redacted_details = _redact_sensitive(details) if details else None

        event = {
            "timestamp": isonow(),
            "action": action,
            "device": device,
            "details": redacted_details,
            "status": status,
            "role": role,
        }
        if user is not None:
            event["user"] = user
        self._event_log.append(event)
        self.save()

        # Forward to SIEM if enabled
        try:
            from core.siem import get_siem_forwarder
            siem = get_siem_forwarder()
            if siem.config.enabled:
                # Map status to severity
                severity_map = {
                    "success": "info",
                    "error": "error",
                    "warning": "warning",
                    "forbidden": "warning",
                    "info": "info",
                }
                siem.send_security_event(
                    event_type=action,
                    user=role if role != "system" else None,
                    action=redacted_details or action,  # Use redacted details
                    status=status,
                    severity=severity_map.get(status, "info"),
                    details={"device": device} if device else None,
                )
        except Exception:
            # Don't let SIEM failures affect normal operation
            pass

        # Fire async memory callback if configured
        if self._memory_callback is not None:
            try:
                asyncio.create_task(
                    self._memory_callback(action, device, details, status)
                )
            except RuntimeError:
                # No event loop running (sync context) - skip memory recording
                pass

        return event

    def get_events(
        self,
        limit: int = 50,
        device: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[dict]:
        """
        Get events from the log with optional filtering.

        Args:
            limit: Maximum number of events to return
            device: Filter by device name
            action: Filter by action type

        Returns:
            List of event dicts, most recent first
        """
        if not self._loaded:
            self.load()

        events = list(self._event_log)

        # Apply filters
        if device:
            events = [e for e in events if e.get("device") == device]
        if action:
            events = [e for e in events if e.get("action") == action]

        # Return most recent first, limited
        return list(reversed(events[-limit:]))

    def clear(self) -> None:
        """Clear all events from the log."""
        self._event_log.clear()
        self.save()

    def set_memory_callback(
        self,
        callback: Optional[Callable[..., Awaitable[Any]]],
    ) -> None:
        """
        Set an async callback for memory system integration.

        The callback will be called with (action, device, details, status)
        whenever an event is logged.

        Args:
            callback: Async function to call, or None to disable
        """
        self._memory_callback = callback

    @property
    def events(self) -> deque:
        """Direct access to the event deque (for compatibility)."""
        if not self._loaded:
            self.load()
        return self._event_log


# =============================================================================
# Module-level singleton and convenience functions
# =============================================================================

# Global singleton instance
event_logger = EventLogger()


def load_event_log() -> None:
    """Load the event log from disk."""
    event_logger.load()


def save_event_log() -> None:
    """Save the event log to disk."""
    event_logger.save()


def log_event(
    action: str,
    device: Optional[str] = None,
    details: Optional[str] = None,
    status: str = "success",
    role: str = "system",
    user: Optional[str] = None,
) -> dict:
    """Log an event to the audit trail."""
    return event_logger.log(action, device, details, status, role, user=user)


def get_event_log(
    limit: int = 50,
    device: Optional[str] = None,
    action: Optional[str] = None,
) -> list[dict]:
    """Get events from the log."""
    return event_logger.get_events(limit, device, action)


def clear_event_log() -> None:
    """Clear all events from the log."""
    event_logger.clear()


# Auto-load on import
load_event_log()
