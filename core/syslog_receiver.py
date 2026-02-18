"""
Syslog Receiver for NetworkOps.

Receives and processes syslog messages from network devices in real-time.
Supports both RFC 3164 (BSD) and RFC 5424 syslog formats.

Features:
- UDP and TCP listeners
- RFC 3164 and RFC 5424 parsing
- Event buffering with configurable retention
- Severity-based filtering
- Device name extraction from hostname or IP
- Optional webhook alerts for critical events

Usage:
    from core.syslog_receiver import SyslogReceiver, get_receiver

    # Start receiver
    receiver = get_receiver()
    await receiver.start()

    # Query recent events
    events = await receiver.get_events(device="R1", severity="error", limit=50)

    # Stop receiver
    await receiver.stop()
"""

import asyncio
import json
import logging
import os
import re
import socket
from collections import deque
from dataclasses import dataclass, field, asdict
from core.timestamps import isonow
from enum import IntEnum
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", 1514))  # Use 1514 to avoid root
SYSLOG_BUFFER_SIZE = int(os.environ.get("SYSLOG_BUFFER_SIZE", 10000))
SYSLOG_RETENTION_MINUTES = int(os.environ.get("SYSLOG_RETENTION_MINUTES", 60))

# =============================================================================
# Syslog Constants
# =============================================================================

class SyslogFacility(IntEnum):
    """Syslog facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    NTP = 12
    AUDIT = 13
    ALERT = 14
    CLOCK = 15
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """Syslog severity levels."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


SEVERITY_NAMES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert",
    15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SyslogEvent:
    """Parsed syslog event."""
    timestamp: str
    received_at: str
    source_ip: str
    hostname: str
    device_name: Optional[str]  # Resolved from hostname or IP lookup
    facility: int
    facility_name: str
    severity: int
    severity_name: str
    program: Optional[str]
    pid: Optional[int]
    message: str
    raw: str

    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# Syslog Parser
# =============================================================================

# RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME MESSAGE
RFC3164_PATTERN = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<message>.*)"
)

# RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\[.*?\]|-)\s*"
    r"(?P<message>.*)"
)

# Cisco IOS format: %FACILITY-SEVERITY-MNEMONIC: Message
CISCO_MSG_PATTERN = re.compile(
    r"%(?P<facility>\w+)-(?P<severity>\d+)-(?P<mnemonic>\w+):\s*(?P<message>.*)"
)


def parse_syslog_message(data: bytes, source_ip: str) -> Optional[SyslogEvent]:
    """
    Parse a syslog message (RFC 3164 or RFC 5424 format).

    Args:
        data: Raw syslog message bytes
        source_ip: Source IP address

    Returns:
        SyslogEvent or None if parsing fails
    """
    try:
        # Decode message
        text = data.decode('utf-8', errors='replace').strip()
        if not text:
            return None

        received_at = isonow()
        timestamp = received_at
        hostname = source_ip
        program = None
        pid = None
        message = text
        facility = 1  # user
        severity = 6  # info

        # Try RFC 5424 first
        match = RFC5424_PATTERN.match(text)
        if match:
            pri = int(match.group("pri"))
            facility = pri >> 3
            severity = pri & 7
            timestamp = match.group("timestamp")
            hostname = match.group("hostname")
            program = match.group("appname") if match.group("appname") != "-" else None
            pid_str = match.group("procid")
            pid = int(pid_str) if pid_str != "-" and pid_str.isdigit() else None
            message = match.group("message")
        else:
            # Try RFC 3164
            match = RFC3164_PATTERN.match(text)
            if match:
                pri = int(match.group("pri"))
                facility = pri >> 3
                severity = pri & 7
                timestamp = match.group("timestamp")
                hostname = match.group("hostname")
                message = match.group("message")

                # Extract program name and PID if present
                # Format: program[pid]: message
                prog_match = re.match(r"(\S+?)(?:\[(\d+)\])?:\s*(.*)", message)
                if prog_match:
                    program = prog_match.group(1)
                    pid = int(prog_match.group(2)) if prog_match.group(2) else None
                    message = prog_match.group(3)

        # Try to resolve device name from hostname
        device_name = _resolve_device_name(hostname, source_ip)

        return SyslogEvent(
            timestamp=timestamp,
            received_at=received_at,
            source_ip=source_ip,
            hostname=hostname,
            device_name=device_name,
            facility=facility,
            facility_name=FACILITY_NAMES.get(facility, f"facility{facility}"),
            severity=severity,
            severity_name=SEVERITY_NAMES.get(severity, f"severity{severity}"),
            program=program,
            pid=pid,
            message=message,
            raw=text,
        )

    except Exception as e:
        logger.warning(f"Failed to parse syslog message: {e}")
        return None


def _resolve_device_name(hostname: str, source_ip: str) -> Optional[str]:
    """
    Resolve device name from hostname or IP.

    Tries to match against known devices in inventory.
    """
    try:
        from config.devices import DEVICES

        # Check if hostname matches a device name
        for device_name in DEVICES:
            if hostname.lower() == device_name.lower():
                return device_name
            # Check if hostname starts with device name (e.g., "R1.lab.local")
            if hostname.lower().startswith(device_name.lower()):
                return device_name

        # Check if source IP matches a device
        for device_name, device_config in DEVICES.items():
            if device_config.get("host") == source_ip:
                return device_name

        return None
    except ImportError:
        return None


# =============================================================================
# Syslog Receiver
# =============================================================================

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog."""

    def __init__(self, callback: Callable[[bytes, tuple], None]):
        self.callback = callback
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self.callback(data, addr)

    def error_received(self, exc):
        logger.error(f"Syslog UDP error: {exc}")


class SyslogReceiver:
    """
    Async syslog receiver with event buffering.

    Listens for syslog messages on UDP and stores them in a circular buffer.
    """

    def __init__(
        self,
        port: int = SYSLOG_PORT,
        buffer_size: int = SYSLOG_BUFFER_SIZE,
        alert_callback: Callable[[SyslogEvent], Any] = None,
    ):
        """
        Initialize syslog receiver.

        Args:
            port: UDP port to listen on (default: 1514)
            buffer_size: Maximum events to buffer (default: 10000)
            alert_callback: Optional callback for critical events
        """
        self.port = port
        self.buffer_size = buffer_size
        self.alert_callback = alert_callback

        self._events: deque[SyslogEvent] = deque(maxlen=buffer_size)
        self._transport = None
        self._protocol = None
        self._running = False
        self._stats = {
            "received": 0,
            "parsed": 0,
            "parse_errors": 0,
            "alerts_triggered": 0,
        }

    async def start(self) -> bool:
        """Start listening for syslog messages."""
        if self._running:
            return True

        try:
            loop = asyncio.get_event_loop()
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self._handle_message),
                local_addr=("0.0.0.0", self.port),  # nosec B104 — syslog receiver must bind all interfaces
                family=socket.AF_INET,
            )
            self._running = True
            logger.info(f"Syslog receiver started on UDP port {self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start syslog receiver: {e}")
            return False

    async def stop(self):
        """Stop the syslog receiver."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None
        self._running = False
        logger.info("Syslog receiver stopped")

    def _handle_message(self, data: bytes, addr: tuple):
        """Handle incoming syslog message."""
        self._stats["received"] += 1
        source_ip = addr[0]

        event = parse_syslog_message(data, source_ip)
        if event:
            self._stats["parsed"] += 1
            self._events.append(event)

            # Trigger alert for critical events
            if event.severity <= SyslogSeverity.ERROR and self.alert_callback:
                try:
                    self._stats["alerts_triggered"] += 1
                    asyncio.create_task(self._trigger_alert(event))
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")
        else:
            self._stats["parse_errors"] += 1

    async def _trigger_alert(self, event: SyslogEvent):
        """Trigger alert callback for critical event."""
        if self.alert_callback:
            try:
                result = self.alert_callback(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    async def get_events(
        self,
        device: str = None,
        severity: str = None,
        min_severity: int = None,
        facility: str = None,
        search: str = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Get filtered syslog events.

        Args:
            device: Filter by device name
            severity: Filter by exact severity name (e.g., "error")
            min_severity: Filter by minimum severity (0=emergency to 7=debug)
            facility: Filter by facility name
            search: Search text in message
            limit: Maximum events to return

        Returns:
            List of event dictionaries (newest first)
        """
        results = []

        for event in reversed(self._events):
            # Apply filters
            if device and event.device_name != device:
                continue
            if severity and event.severity_name != severity:
                continue
            if min_severity is not None and event.severity > min_severity:
                continue
            if facility and event.facility_name != facility:
                continue
            if search and search.lower() not in event.message.lower():
                continue

            results.append(event.to_dict())

            if len(results) >= limit:
                break

        return results

    async def get_stats(self) -> dict:
        """Get receiver statistics."""
        return {
            "running": self._running,
            "port": self.port,
            "buffer_size": self.buffer_size,
            "events_buffered": len(self._events),
            "stats": self._stats.copy(),
        }

    async def clear_events(self) -> int:
        """Clear event buffer. Returns count of cleared events."""
        count = len(self._events)
        self._events.clear()
        return count

    async def get_device_summary(self) -> dict:
        """Get event count summary by device."""
        summary = {}
        for event in self._events:
            device = event.device_name or event.source_ip
            if device not in summary:
                summary[device] = {
                    "total": 0,
                    "by_severity": {s: 0 for s in SEVERITY_NAMES.values()},
                }
            summary[device]["total"] += 1
            summary[device]["by_severity"][event.severity_name] += 1

        return summary


# =============================================================================
# Global Receiver Instance
# =============================================================================

_receiver: Optional[SyslogReceiver] = None


def get_receiver() -> SyslogReceiver:
    """Get the global syslog receiver instance."""
    global _receiver
    if _receiver is None:
        _receiver = SyslogReceiver()
    return _receiver


async def start_receiver() -> bool:
    """Start the global syslog receiver."""
    return await get_receiver().start()


async def stop_receiver():
    """Stop the global syslog receiver."""
    await get_receiver().stop()


async def get_syslog_events(
    device: str = None,
    severity: str = None,
    min_severity: int = None,
    facility: str = None,
    search: str = None,
    limit: int = 100,
) -> list[dict]:
    """Get filtered syslog events from the global receiver."""
    return await get_receiver().get_events(
        device=device,
        severity=severity,
        min_severity=min_severity,
        facility=facility,
        search=search,
        limit=limit,
    )


async def get_syslog_stats() -> dict:
    """Get syslog receiver statistics."""
    return await get_receiver().get_stats()


async def get_syslog_summary() -> dict:
    """Get syslog event summary by device."""
    return await get_receiver().get_device_summary()


async def clear_syslog_events() -> int:
    """Clear syslog event buffer."""
    return await get_receiver().clear_events()


# =============================================================================
# Webhook Alert Integration
# =============================================================================

async def default_alert_callback(event: SyslogEvent):
    """
    Default alert callback that sends webhook notifications.

    Only triggers for error severity or higher from known devices.
    """
    if event.severity > SyslogSeverity.ERROR:
        return

    if not event.device_name:
        return

    try:
        from core.webhooks import send_alert

        severity_map = {
            0: "critical",  # emergency
            1: "critical",  # alert
            2: "critical",
            3: "error",
        }

        await send_alert(
            message=f"{event.program or 'syslog'}: {event.message}",
            title=f"Syslog Alert: {event.device_name}",
            severity=severity_map.get(event.severity, "warning"),
            fields={
                "Device": event.device_name,
                "Severity": event.severity_name.upper(),
                "Facility": event.facility_name,
                "Source IP": event.source_ip,
            }
        )
    except ImportError:
        pass
    except Exception as e:
        logger.error(f"Failed to send syslog alert: {e}")
