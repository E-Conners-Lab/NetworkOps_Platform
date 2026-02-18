"""
Event Correlation and Root Cause Analysis for NetworkOps.

Collects events from multiple sources (syslog, interface changes, protocol events)
and correlates them to identify root causes of network issues.

Features:
- Multi-source event aggregation
- Time-window based correlation
- Topology-aware correlation (upstream/downstream impact)
- Pattern-based root cause identification
- Event deduplication and suppression

Usage:
    from core.event_correlation import EventCorrelator

    correlator = EventCorrelator()

    # Register events
    correlator.add_event(event1)
    correlator.add_event(event2)

    # Run correlation
    incidents = correlator.correlate()

    # Get root cause analysis
    rca = correlator.analyze_root_cause(incident_id)
"""

import asyncio
import json
import logging
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

EVENT_DB = Path(__file__).parent.parent / "data" / "events.db"

# Correlation time windows
CORRELATION_WINDOW_SECONDS = 60  # Events within 60s may be related
SUPPRESSION_WINDOW_SECONDS = 300  # Suppress duplicate events for 5 min
EVENT_RETENTION_DAYS = 30  # Keep events for 30 days


# =============================================================================
# Data Models
# =============================================================================

class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventType(str, Enum):
    INTERFACE_DOWN = "interface_down"
    INTERFACE_UP = "interface_up"
    INTERFACE_FLAP = "interface_flap"
    OSPF_NEIGHBOR_DOWN = "ospf_neighbor_down"
    OSPF_NEIGHBOR_UP = "ospf_neighbor_up"
    BGP_PEER_DOWN = "bgp_peer_down"
    BGP_PEER_UP = "bgp_peer_up"
    EIGRP_NEIGHBOR_DOWN = "eigrp_neighbor_down"
    EIGRP_NEIGHBOR_UP = "eigrp_neighbor_up"
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    CONFIG_CHANGE = "config_change"
    SYSLOG_ERROR = "syslog_error"
    DEVICE_UNREACHABLE = "device_unreachable"
    DEVICE_REACHABLE = "device_reachable"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


@dataclass
class NetworkEvent:
    """A single network event."""
    event_id: str
    device: str
    event_type: EventType
    severity: EventSeverity
    timestamp: str
    message: str
    source: str = "unknown"  # syslog, snmp, telemetry, etc.
    interface: str = None
    neighbor: str = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkEvent":
        return cls(
            event_id=data["event_id"],
            device=data["device"],
            event_type=EventType(data["event_type"]),
            severity=EventSeverity(data["severity"]),
            timestamp=data["timestamp"],
            message=data["message"],
            source=data.get("source", "unknown"),
            interface=data.get("interface"),
            neighbor=data.get("neighbor"),
            details=data.get("details", {}),
        )


@dataclass
class CorrelatedIncident:
    """A group of correlated events representing an incident."""
    incident_id: str
    root_cause_event: str  # Event ID of probable root cause
    status: IncidentStatus
    severity: EventSeverity
    created_at: str
    updated_at: str
    affected_devices: list[str]
    event_ids: list[str]
    root_cause_analysis: str
    impact_summary: str
    remediation_hints: list[str]

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "status": self.status.value,
            "severity": self.severity.value,
        }


# =============================================================================
# Correlation Rules
# =============================================================================

# Pattern rules for identifying related events
CORRELATION_RULES = [
    {
        "name": "interface_protocol_cascade",
        "description": "Interface down causes protocol neighbor loss",
        "trigger": EventType.INTERFACE_DOWN,
        "related": [
            EventType.OSPF_NEIGHBOR_DOWN,
            EventType.BGP_PEER_DOWN,
            EventType.EIGRP_NEIGHBOR_DOWN,
        ],
        "root_cause": "Interface failure",
    },
    {
        "name": "interface_flapping",
        "description": "Multiple up/down events on same interface",
        "trigger": EventType.INTERFACE_DOWN,
        "related": [EventType.INTERFACE_UP, EventType.INTERFACE_DOWN],
        "root_cause": "Interface flapping",
        "min_events": 3,
    },
    {
        "name": "device_unreachable_cascade",
        "description": "Device unreachable causes downstream issues",
        "trigger": EventType.DEVICE_UNREACHABLE,
        "related": [
            EventType.OSPF_NEIGHBOR_DOWN,
            EventType.BGP_PEER_DOWN,
            EventType.EIGRP_NEIGHBOR_DOWN,
        ],
        "root_cause": "Device failure or connectivity loss",
    },
    {
        "name": "resource_exhaustion",
        "description": "High CPU/memory causes protocol timeouts",
        "trigger": EventType.HIGH_CPU,
        "related": [
            EventType.OSPF_NEIGHBOR_DOWN,
            EventType.BGP_PEER_DOWN,
            EventType.HIGH_MEMORY,
        ],
        "root_cause": "Resource exhaustion",
    },
]

# Remediation hints based on event type
REMEDIATION_HINTS = {
    EventType.INTERFACE_DOWN: [
        "Check physical layer (cables, SFPs)",
        "Verify interface configuration",
        "Check for admin shutdown",
        "Review error counters",
    ],
    EventType.INTERFACE_FLAP: [
        "Check for duplex mismatch",
        "Verify cable quality",
        "Check for spanning tree issues",
        "Review interface error counters",
    ],
    EventType.OSPF_NEIGHBOR_DOWN: [
        "Verify OSPF configuration (area, network type)",
        "Check MTU mismatch",
        "Verify interface is in correct OSPF area",
        "Check authentication settings",
    ],
    EventType.BGP_PEER_DOWN: [
        "Verify BGP neighbor configuration",
        "Check TCP connectivity on port 179",
        "Verify AS numbers and router IDs",
        "Check for route filtering issues",
    ],
    EventType.HIGH_CPU: [
        "Identify high-CPU processes",
        "Check for route flapping",
        "Review logging and debug settings",
        "Check for control plane issues",
    ],
    EventType.DEVICE_UNREACHABLE: [
        "Verify management network connectivity",
        "Check device power and boot status",
        "Verify SSH/NETCONF accessibility",
        "Check for ACL blocking management traffic",
    ],
}


# =============================================================================
# Event Correlation Engine
# =============================================================================

class EventCorrelator:
    """
    Network event correlation and root cause analysis.
    """

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or EVENT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for events."""
        with sqlite3.connect(self.db_path) as conn:
            # Events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    device TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    message TEXT,
                    source TEXT,
                    interface TEXT,
                    neighbor TEXT,
                    details TEXT,
                    correlated BOOLEAN DEFAULT FALSE,
                    incident_id TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_device_time
                ON events(device, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type, timestamp)
            """)

            # Incidents table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    root_cause_event TEXT,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    affected_devices TEXT,
                    event_ids TEXT,
                    root_cause_analysis TEXT,
                    impact_summary TEXT,
                    remediation_hints TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(status, created_at)
            """)

            # Event suppression table (for deduplication)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS suppression (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    suppression_key TEXT UNIQUE NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)

            conn.commit()

    def add_event(self, event: NetworkEvent) -> bool:
        """
        Add a new event to the correlation engine.

        Returns:
            True if event was added, False if suppressed
        """
        # Check for suppression
        if self._is_suppressed(event):
            logger.debug(f"Event suppressed: {event.event_id}")
            return False

        # Save event
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO events
                (event_id, device, event_type, severity, timestamp, message,
                 source, interface, neighbor, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.device,
                event.event_type.value,
                event.severity.value,
                event.timestamp,
                event.message,
                event.source,
                event.interface,
                event.neighbor,
                json.dumps(event.details),
            ))
            conn.commit()

        # Add suppression
        self._add_suppression(event)

        return True

    def _is_suppressed(self, event: NetworkEvent) -> bool:
        """Check if event should be suppressed."""
        key = self._suppression_key(event)
        now = isonow()

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT expires_at FROM suppression
                WHERE suppression_key = ? AND expires_at > ?
            """, (key, now)).fetchone()

            return row is not None

    def _add_suppression(self, event: NetworkEvent):
        """Add suppression entry for event."""
        key = self._suppression_key(event)
        expires = (now() + timedelta(seconds=SUPPRESSION_WINDOW_SECONDS)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO suppression (suppression_key, expires_at)
                VALUES (?, ?)
            """, (key, expires))
            conn.commit()

    def _suppression_key(self, event: NetworkEvent) -> str:
        """Generate suppression key for event deduplication."""
        return f"{event.device}:{event.event_type.value}:{event.interface or ''}"

    def correlate(self) -> list[CorrelatedIncident]:
        """
        Run correlation on uncorrelated events.

        Returns:
            List of new incidents created
        """
        # Get uncorrelated events
        events = self._get_uncorrelated_events()
        if not events:
            return []

        # Group by time window
        time_groups = self._group_by_time_window(events)

        incidents = []
        for group in time_groups:
            incident = self._analyze_event_group(group)
            if incident:
                self._save_incident(incident)
                self._mark_events_correlated(incident)
                incidents.append(incident)

        return incidents

    def _get_uncorrelated_events(self) -> list[NetworkEvent]:
        """Get events that haven't been correlated yet."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM events
                WHERE correlated = FALSE
                ORDER BY timestamp
            """).fetchall()

            return [self._row_to_event(row) for row in rows]

    def _row_to_event(self, row) -> NetworkEvent:
        """Convert database row to NetworkEvent."""
        return NetworkEvent(
            event_id=row["event_id"],
            device=row["device"],
            event_type=EventType(row["event_type"]),
            severity=EventSeverity(row["severity"]),
            timestamp=row["timestamp"],
            message=row["message"],
            source=row["source"],
            interface=row["interface"],
            neighbor=row["neighbor"],
            details=json.loads(row["details"]) if row["details"] else {},
        )

    def _group_by_time_window(
        self,
        events: list[NetworkEvent],
    ) -> list[list[NetworkEvent]]:
        """Group events by correlation time window."""
        if not events:
            return []

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        groups = []
        current_group = [sorted_events[0]]

        for event in sorted_events[1:]:
            last_time = datetime.fromisoformat(current_group[-1].timestamp)
            curr_time = datetime.fromisoformat(event.timestamp)

            if (curr_time - last_time).total_seconds() <= CORRELATION_WINDOW_SECONDS:
                current_group.append(event)
            else:
                if len(current_group) > 1 or self._is_significant(current_group[0]):
                    groups.append(current_group)
                current_group = [event]

        if len(current_group) > 1 or self._is_significant(current_group[0]):
            groups.append(current_group)

        return groups

    def _is_significant(self, event: NetworkEvent) -> bool:
        """Check if single event is significant enough for incident."""
        significant_types = [
            EventType.DEVICE_UNREACHABLE,
            EventType.INTERFACE_DOWN,
            EventType.OSPF_NEIGHBOR_DOWN,
            EventType.BGP_PEER_DOWN,
        ]
        return event.event_type in significant_types and event.severity in [
            EventSeverity.CRITICAL,
            EventSeverity.HIGH,
        ]

    def _analyze_event_group(
        self,
        events: list[NetworkEvent],
    ) -> Optional[CorrelatedIncident]:
        """Analyze a group of events to create an incident."""
        if not events:
            return None

        # Try to match correlation rules
        root_cause_event = None
        root_cause_analysis = ""
        remediation_hints = []

        for rule in CORRELATION_RULES:
            trigger_events = [e for e in events if e.event_type == rule["trigger"]]
            if not trigger_events:
                continue

            related_events = [
                e for e in events
                if e.event_type in rule["related"] and e not in trigger_events
            ]

            min_events = rule.get("min_events", 2)
            if len(trigger_events) + len(related_events) >= min_events:
                # Found matching rule
                root_cause_event = trigger_events[0]
                root_cause_analysis = rule["root_cause"]
                remediation_hints = REMEDIATION_HINTS.get(
                    root_cause_event.event_type, []
                )
                break

        # If no rule matched, use the earliest highest-severity event
        if not root_cause_event:
            sorted_by_severity = sorted(
                events,
                key=lambda e: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[e.severity.value],
                    e.timestamp,
                ),
            )
            root_cause_event = sorted_by_severity[0]
            root_cause_analysis = f"Unclassified incident triggered by {root_cause_event.event_type.value}"
            remediation_hints = REMEDIATION_HINTS.get(root_cause_event.event_type, [])

        # Determine affected devices
        affected_devices = list(set(e.device for e in events))

        # Calculate overall severity
        severities = [e.severity for e in events]
        if EventSeverity.CRITICAL in severities:
            severity = EventSeverity.CRITICAL
        elif EventSeverity.HIGH in severities:
            severity = EventSeverity.HIGH
        elif EventSeverity.MEDIUM in severities:
            severity = EventSeverity.MEDIUM
        else:
            severity = EventSeverity.LOW

        # Generate impact summary
        impact_summary = self._generate_impact_summary(events, affected_devices)

        now = isonow()
        return CorrelatedIncident(
            incident_id=str(uuid4())[:8],
            root_cause_event=root_cause_event.event_id,
            status=IncidentStatus.OPEN,
            severity=severity,
            created_at=now,
            updated_at=now,
            affected_devices=affected_devices,
            event_ids=[e.event_id for e in events],
            root_cause_analysis=root_cause_analysis,
            impact_summary=impact_summary,
            remediation_hints=remediation_hints,
        )

    def _generate_impact_summary(
        self,
        events: list[NetworkEvent],
        affected_devices: list[str],
    ) -> str:
        """Generate human-readable impact summary."""
        event_counts = defaultdict(int)
        for e in events:
            event_counts[e.event_type.value] += 1

        parts = [
            f"{count} {event_type.replace('_', ' ')} event(s)"
            for event_type, count in event_counts.items()
        ]
        event_summary = ", ".join(parts)

        return (
            f"Affects {len(affected_devices)} device(s): {', '.join(affected_devices)}. "
            f"Events: {event_summary}."
        )

    def _save_incident(self, incident: CorrelatedIncident):
        """Save incident to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO incidents
                (incident_id, root_cause_event, status, severity, created_at,
                 updated_at, affected_devices, event_ids, root_cause_analysis,
                 impact_summary, remediation_hints)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.root_cause_event,
                incident.status.value,
                incident.severity.value,
                incident.created_at,
                incident.updated_at,
                json.dumps(incident.affected_devices),
                json.dumps(incident.event_ids),
                incident.root_cause_analysis,
                incident.impact_summary,
                json.dumps(incident.remediation_hints),
            ))
            conn.commit()

    def _mark_events_correlated(self, incident: CorrelatedIncident):
        """Mark events as correlated."""
        with sqlite3.connect(self.db_path) as conn:
            for event_id in incident.event_ids:
                conn.execute("""
                    UPDATE events
                    SET correlated = TRUE, incident_id = ?
                    WHERE event_id = ?
                """, (incident.incident_id, event_id))
            conn.commit()

    def get_incident(self, incident_id: str) -> Optional[CorrelatedIncident]:
        """Get an incident by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM incidents WHERE incident_id = ?
            """, (incident_id,)).fetchone()

            if not row:
                return None

            return CorrelatedIncident(
                incident_id=row["incident_id"],
                root_cause_event=row["root_cause_event"],
                status=IncidentStatus(row["status"]),
                severity=EventSeverity(row["severity"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                affected_devices=json.loads(row["affected_devices"]),
                event_ids=json.loads(row["event_ids"]),
                root_cause_analysis=row["root_cause_analysis"],
                impact_summary=row["impact_summary"],
                remediation_hints=json.loads(row["remediation_hints"]),
            )

    def get_incidents(
        self,
        status: str = None,
        severity: str = None,
        device: str = None,
        hours: int = 24,
    ) -> list[CorrelatedIncident]:
        """Get incidents with optional filters."""
        cutoff = (now() - timedelta(hours=hours)).isoformat()

        query = "SELECT * FROM incidents WHERE created_at >= ?"
        params = [cutoff]

        if status:
            query += " AND status = ?"
            params.append(status)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC"

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

            incidents = []
            for row in rows:
                incident = CorrelatedIncident(
                    incident_id=row["incident_id"],
                    root_cause_event=row["root_cause_event"],
                    status=IncidentStatus(row["status"]),
                    severity=EventSeverity(row["severity"]),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    affected_devices=json.loads(row["affected_devices"]),
                    event_ids=json.loads(row["event_ids"]),
                    root_cause_analysis=row["root_cause_analysis"],
                    impact_summary=row["impact_summary"],
                    remediation_hints=json.loads(row["remediation_hints"]),
                )

                # Filter by device if specified
                if device and device not in incident.affected_devices:
                    continue

                incidents.append(incident)

            return incidents

    def update_incident_status(
        self,
        incident_id: str,
        status: IncidentStatus,
    ) -> Optional[CorrelatedIncident]:
        """Update incident status."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE incident_id = ?
            """, (status.value, isonow(), incident_id))
            conn.commit()

        return self.get_incident(incident_id)

    def get_events_for_incident(self, incident_id: str) -> list[NetworkEvent]:
        """Get all events belonging to an incident."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM events
                WHERE incident_id = ?
                ORDER BY timestamp
            """, (incident_id,)).fetchall()

            return [self._row_to_event(row) for row in rows]

    def analyze_root_cause(self, incident_id: str) -> dict:
        """
        Perform detailed root cause analysis for an incident.

        Returns comprehensive RCA report.
        """
        incident = self.get_incident(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        events = self.get_events_for_incident(incident_id)
        root_event = next(
            (e for e in events if e.event_id == incident.root_cause_event),
            events[0] if events else None,
        )

        # Build timeline
        timeline = [
            {
                "time": e.timestamp,
                "device": e.device,
                "event": e.event_type.value,
                "message": e.message,
                "is_root_cause": e.event_id == incident.root_cause_event,
            }
            for e in sorted(events, key=lambda e: e.timestamp)
        ]

        # Analyze event chain
        event_chain = self._analyze_event_chain(events, root_event)

        return {
            "incident_id": incident_id,
            "status": incident.status.value,
            "severity": incident.severity.value,
            "created_at": incident.created_at,
            "root_cause": {
                "event_id": root_event.event_id if root_event else None,
                "device": root_event.device if root_event else None,
                "event_type": root_event.event_type.value if root_event else None,
                "message": root_event.message if root_event else None,
                "analysis": incident.root_cause_analysis,
            },
            "impact": {
                "affected_devices": incident.affected_devices,
                "total_events": len(events),
                "summary": incident.impact_summary,
            },
            "timeline": timeline,
            "event_chain": event_chain,
            "remediation": {
                "hints": incident.remediation_hints,
                "priority": self._determine_priority(incident, events),
            },
        }

    def _analyze_event_chain(
        self,
        events: list[NetworkEvent],
        root_event: NetworkEvent,
    ) -> list[dict]:
        """Analyze the chain of events from root cause."""
        if not root_event or not events:
            return []

        chain = []
        root_time = datetime.fromisoformat(root_event.timestamp)

        for event in sorted(events, key=lambda e: e.timestamp):
            event_time = datetime.fromisoformat(event.timestamp)
            delta = (event_time - root_time).total_seconds()

            chain.append({
                "event_id": event.event_id,
                "device": event.device,
                "event_type": event.event_type.value,
                "seconds_after_root": delta,
                "is_root": event.event_id == root_event.event_id,
            })

        return chain

    def _determine_priority(
        self,
        incident: CorrelatedIncident,
        events: list[NetworkEvent],
    ) -> str:
        """Determine remediation priority."""
        # Critical = multiple devices or critical severity
        if len(incident.affected_devices) > 2:
            return "P1 - Critical"
        if incident.severity == EventSeverity.CRITICAL:
            return "P1 - Critical"

        # High = single device critical or multiple high events
        if incident.severity == EventSeverity.HIGH:
            return "P2 - High"

        # Medium and below
        return "P3 - Medium"

    async def collect_live_events(
        self,
        device_name: str,
    ) -> list[NetworkEvent]:
        """
        Collect live events from a device by checking current state.

        This is for ad-hoc event collection when syslog isn't available.
        """
        from config.devices import DEVICES
        from core.scrapli_manager import get_ios_xe_connection

        if device_name not in DEVICES:
            raise ValueError(f"Device '{device_name}' not found")

        events = []
        timestamp = isonow()

        try:
            async with get_ios_xe_connection(device_name) as conn:
                # Check interface status
                resp = await conn.send_command("show ip interface brief")
                for event in self._parse_interface_events(
                    resp.result, device_name, timestamp
                ):
                    events.append(event)

                # Check OSPF neighbors
                resp = await conn.send_command("show ip ospf neighbor")
                for event in self._parse_ospf_events(
                    resp.result, device_name, timestamp
                ):
                    events.append(event)

                # Check BGP neighbors
                resp = await conn.send_command("show ip bgp summary")
                for event in self._parse_bgp_events(
                    resp.result, device_name, timestamp
                ):
                    events.append(event)

        except Exception as e:
            # Device unreachable
            events.append(NetworkEvent(
                event_id=str(uuid4())[:8],
                device=device_name,
                event_type=EventType.DEVICE_UNREACHABLE,
                severity=EventSeverity.CRITICAL,
                timestamp=timestamp,
                message=f"Cannot connect to {device_name}: {e}",
                source="health_check",
            ))

        return events

    def _parse_interface_events(
        self,
        output: str,
        device: str,
        timestamp: str,
    ) -> list[NetworkEvent]:
        """Parse interface status for down interfaces."""
        events = []

        for line in output.split("\n"):
            # Match: Interface IP-Address OK? Method Status Protocol
            match = re.match(
                r"(\S+)\s+[\d.]+\s+\w+\s+\w+\s+(\w+)\s+(\w+)",
                line.strip(),
            )
            if match:
                interface, admin_status, line_protocol = match.groups()

                # Skip management and loopback
                if any(skip in interface for skip in ["Loopback", "Gi4", "GigabitEthernet4"]):
                    continue

                if line_protocol.lower() == "down":
                    events.append(NetworkEvent(
                        event_id=str(uuid4())[:8],
                        device=device,
                        event_type=EventType.INTERFACE_DOWN,
                        severity=EventSeverity.HIGH,
                        timestamp=timestamp,
                        message=f"Interface {interface} is down",
                        source="health_check",
                        interface=interface,
                    ))

        return events

    def _parse_ospf_events(
        self,
        output: str,
        device: str,
        timestamp: str,
    ) -> list[NetworkEvent]:
        """Parse OSPF neighbor status."""
        events = []

        # Look for neighbors not in FULL state
        for line in output.split("\n"):
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)/",
                line.strip(),
            )
            if match:
                neighbor_id, state = match.groups()
                if state.upper() not in ["FULL", "2WAY"]:
                    events.append(NetworkEvent(
                        event_id=str(uuid4())[:8],
                        device=device,
                        event_type=EventType.OSPF_NEIGHBOR_DOWN,
                        severity=EventSeverity.HIGH,
                        timestamp=timestamp,
                        message=f"OSPF neighbor {neighbor_id} in {state} state",
                        source="health_check",
                        neighbor=neighbor_id,
                    ))

        return events

    def _parse_bgp_events(
        self,
        output: str,
        device: str,
        timestamp: str,
    ) -> list[NetworkEvent]:
        """Parse BGP summary for down peers."""
        events = []

        for line in output.split("\n"):
            # Match BGP neighbor line
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)",
                line.strip(),
            )
            if match:
                neighbor, state = match.groups()
                # Non-numeric state means not established
                if not state.isdigit() and state.lower() not in ["established"]:
                    events.append(NetworkEvent(
                        event_id=str(uuid4())[:8],
                        device=device,
                        event_type=EventType.BGP_PEER_DOWN,
                        severity=EventSeverity.HIGH,
                        timestamp=timestamp,
                        message=f"BGP peer {neighbor} in {state} state",
                        source="health_check",
                        neighbor=neighbor,
                    ))

        return events

    def prune_old_events(self, days: int = None) -> int:
        """Remove events older than retention period."""
        days = days or EVENT_RETENTION_DAYS
        cutoff = (now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM events WHERE timestamp < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
            conn.execute(
                "DELETE FROM suppression WHERE expires_at < ?",
                (isonow(),),
            )
            conn.commit()

        return deleted

    def get_event_stats(self, hours: int = 24) -> dict:
        """Get event statistics."""
        cutoff = (now() - timedelta(hours=hours)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Total events
            total = conn.execute("""
                SELECT COUNT(*) FROM events WHERE timestamp >= ?
            """, (cutoff,)).fetchone()[0]

            # By type
            by_type = dict(conn.execute("""
                SELECT event_type, COUNT(*) FROM events
                WHERE timestamp >= ?
                GROUP BY event_type
            """, (cutoff,)).fetchall())

            # By severity
            by_severity = dict(conn.execute("""
                SELECT severity, COUNT(*) FROM events
                WHERE timestamp >= ?
                GROUP BY severity
            """, (cutoff,)).fetchall())

            # By device
            by_device = dict(conn.execute("""
                SELECT device, COUNT(*) FROM events
                WHERE timestamp >= ?
                GROUP BY device
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """, (cutoff,)).fetchall())

            # Open incidents
            open_incidents = conn.execute("""
                SELECT COUNT(*) FROM incidents WHERE status = 'open'
            """).fetchone()[0]

        return {
            "period_hours": hours,
            "total_events": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "top_devices": by_device,
            "open_incidents": open_incidents,
        }


# =============================================================================
# Global Instance
# =============================================================================

_correlator: Optional[EventCorrelator] = None


def get_event_correlator() -> EventCorrelator:
    """Get the global event correlator instance."""
    global _correlator
    if _correlator is None:
        _correlator = EventCorrelator()
    return _correlator
