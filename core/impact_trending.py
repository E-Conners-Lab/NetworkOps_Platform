"""
Historical Trending for Impact Analysis.

Stores periodic snapshots of device network state (OSPF neighbors, BGP peers,
interface states) to enable baseline comparisons and drift detection.

Features:
- Point-in-time device state snapshots
- Baseline management (set/get known-good state)
- Drift detection (compare current vs baseline)
- Historical trending queries
- SQLite-backed persistent storage

Usage:
    from core.impact_trending import ImpactTrending, get_impact_trending

    trending = get_impact_trending()

    # Capture current state
    snapshot = await trending.capture_snapshot("R1")

    # Set as baseline
    trending.set_baseline("R1", snapshot.snapshot_id)

    # Later, check for drift
    drift = await trending.compare_to_baseline("R1")
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field, asdict
from datetime import timedelta

from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

TRENDING_DB = Path(__file__).parent.parent / "data" / "impact_trending.db"

# Import UnifiedDB for centralized database access
from core.unified_db import UnifiedDB


# =============================================================================
# Data Models
# =============================================================================


class DriftType(str, Enum):
    """Types of state drift detected."""
    OSPF_NEIGHBOR_LOST = "ospf_neighbor_lost"
    OSPF_NEIGHBOR_ADDED = "ospf_neighbor_added"
    OSPF_NEIGHBOR_STATE_CHANGED = "ospf_neighbor_state_changed"
    BGP_PEER_LOST = "bgp_peer_lost"
    BGP_PEER_ADDED = "bgp_peer_added"
    BGP_PEER_STATE_CHANGED = "bgp_peer_state_changed"
    INTERFACE_DOWN = "interface_down"
    INTERFACE_UP = "interface_up"
    ROUTE_COUNT_CHANGED = "route_count_changed"


class DriftSeverity(str, Enum):
    """Severity of detected drift."""
    INFO = "info"  # Expected or minor changes
    WARNING = "warning"  # Unexpected but not critical
    CRITICAL = "critical"  # Potential outage impact


@dataclass
class OSPFNeighborSnapshot:
    """OSPF neighbor state at a point in time."""
    neighbor_id: str
    address: str
    interface: str
    state: str  # FULL/DR, FULL/BDR, etc.
    area: str = "0"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "OSPFNeighborSnapshot":
        return cls(**d)


@dataclass
class BGPPeerSnapshot:
    """BGP peer state at a point in time."""
    peer_ip: str
    peer_asn: int
    state: str  # Established, Idle, Active, etc.
    prefixes_received: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "BGPPeerSnapshot":
        return cls(**d)


@dataclass
class InterfaceSnapshot:
    """Interface state at a point in time."""
    name: str
    status: str  # up, down, administratively down
    ip_address: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "InterfaceSnapshot":
        return cls(**d)


@dataclass
class DeviceSnapshot:
    """Complete device network state at a point in time."""
    snapshot_id: str
    device: str
    timestamp: str
    ospf_neighbors: list[OSPFNeighborSnapshot] = field(default_factory=list)
    bgp_peers: list[BGPPeerSnapshot] = field(default_factory=list)
    interfaces: list[InterfaceSnapshot] = field(default_factory=list)
    route_count: int = 0
    platform: str = "cisco_xe"
    is_baseline: bool = False
    notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "device": self.device,
            "timestamp": self.timestamp,
            "ospf_neighbors": [n.to_dict() for n in self.ospf_neighbors],
            "bgp_peers": [p.to_dict() for p in self.bgp_peers],
            "interfaces": [i.to_dict() for i in self.interfaces],
            "route_count": self.route_count,
            "platform": self.platform,
            "is_baseline": self.is_baseline,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceSnapshot":
        return cls(
            snapshot_id=d["snapshot_id"],
            device=d["device"],
            timestamp=d["timestamp"],
            ospf_neighbors=[OSPFNeighborSnapshot.from_dict(n) for n in d.get("ospf_neighbors", [])],
            bgp_peers=[BGPPeerSnapshot.from_dict(p) for p in d.get("bgp_peers", [])],
            interfaces=[InterfaceSnapshot.from_dict(i) for i in d.get("interfaces", [])],
            route_count=d.get("route_count", 0),
            platform=d.get("platform", "cisco_xe"),
            is_baseline=d.get("is_baseline", False),
            notes=d.get("notes"),
        )


@dataclass
class StateDrift:
    """A detected change between baseline and current state."""
    drift_id: str
    device: str
    detected_at: str
    drift_type: DriftType
    severity: DriftSeverity
    description: str
    baseline_value: Optional[str] = None
    current_value: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "drift_id": self.drift_id,
            "device": self.device,
            "detected_at": self.detected_at,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "details": self.details,
        }


@dataclass
class DriftReport:
    """Complete drift analysis report."""
    device: str
    baseline_timestamp: str
    current_timestamp: str
    total_drifts: int
    critical_count: int
    warning_count: int
    info_count: int
    drifts: list[StateDrift] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "baseline_timestamp": self.baseline_timestamp,
            "current_timestamp": self.current_timestamp,
            "total_drifts": self.total_drifts,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "drifts": [d.to_dict() for d in self.drifts],
            "summary": self.summary,
        }


# =============================================================================
# Impact Trending Engine
# =============================================================================


class ImpactTrending:
    """
    Historical trending and baseline comparison for network device state.
    """

    def __init__(self, db_path: Path = None, db: UnifiedDB = None):
        self.db = db or UnifiedDB.get_instance()
        self.db_path = db_path or self.db.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if db_path and not db:
            # Legacy path: standalone DB for tests
            self._init_db()
        # Otherwise UnifiedDB already initialized schema

    def _connect(self) -> sqlite3.Connection:
        """Get a database connection (unified or standalone)."""
        if self.db:
            return self.db.connect()
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize SQLite database for trending data (standalone mode)."""
        with sqlite3.connect(self.db_path) as conn:
            # Snapshots table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    device TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    ospf_neighbors TEXT,
                    bgp_peers TEXT,
                    interfaces TEXT,
                    route_count INTEGER,
                    platform TEXT,
                    is_baseline INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_snapshots_device
                ON snapshots(device, timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_snapshots_baseline
                ON snapshots(device, is_baseline)
            """)

            # Baselines table (tracks active baseline per device)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    device TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    set_at TEXT NOT NULL,
                    set_by TEXT,
                    reason TEXT,
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
                )
            """)

            # Drift history table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS drift_history (
                    drift_id TEXT PRIMARY KEY,
                    device TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    drift_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    baseline_value TEXT,
                    current_value TEXT,
                    details TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_drift_device
                ON drift_history(device, detected_at)
            """)

            conn.commit()

    # =========================================================================
    # Snapshot Capture
    # =========================================================================

    async def capture_snapshot(
        self,
        device: str,
        notes: Optional[str] = None,
    ) -> DeviceSnapshot:
        """
        Capture current device state as a snapshot.

        Args:
            device: Device name
            notes: Optional notes about this snapshot

        Returns:
            DeviceSnapshot with current state
        """
        from config.devices import DEVICES
        from core.impact_analyzer import ImpactAnalyzer

        if device not in DEVICES:
            raise ValueError(f"Device '{device}' not found")

        snapshot_id = str(uuid.uuid4())[:8]
        timestamp = isonow()

        # Use ImpactAnalyzer's data collection methods
        analyzer = ImpactAnalyzer()

        # Collect data concurrently
        ospf_task = analyzer._collect_ospf_neighbors(device)
        bgp_task = analyzer._collect_bgp_peers(device)
        routing_task = analyzer._collect_routing_table(device)

        ospf_data, bgp_data, routing_data = await asyncio.gather(
            ospf_task, bgp_task, routing_task,
            return_exceptions=True
        )

        # Parse OSPF neighbors
        ospf_neighbors = []
        if isinstance(ospf_data, Exception):
            logger.warning(f"Failed to collect OSPF data for {device}: {ospf_data}")
        elif ospf_data.status == "ok" and ospf_data.data:
            for n in ospf_data.data:
                ospf_neighbors.append(OSPFNeighborSnapshot(
                    neighbor_id=n.get("neighbor_id", ""),
                    address=n.get("address", ""),
                    interface=n.get("interface", ""),
                    state=n.get("state", ""),
                    area=n.get("area", "0"),
                ))

        # Parse BGP peers
        # BGP data format: {'configured': bool, 'peers': [...]} or list of peers
        bgp_peers = []
        if isinstance(bgp_data, Exception):
            logger.warning(f"Failed to collect BGP data for {device}: {bgp_data}")
        elif bgp_data.status == "ok" and bgp_data.data:
            # Handle dict format with 'peers' key
            peers_list = bgp_data.data
            if isinstance(bgp_data.data, dict):
                peers_list = bgp_data.data.get("peers", [])

            for p in peers_list:
                if not isinstance(p, dict):
                    continue
                bgp_peers.append(BGPPeerSnapshot(
                    # Field names vary: neighbor/peer_ip, remote_as/peer_asn
                    peer_ip=p.get("neighbor") or p.get("peer_ip", ""),
                    peer_asn=p.get("remote_as") or p.get("peer_asn", 0),
                    state=p.get("state", ""),
                    prefixes_received=p.get("prefixes_received", 0),
                ))

        # Parse route count
        route_count = 0
        if isinstance(routing_data, Exception):
            logger.warning(f"Failed to collect routing data for {device}: {routing_data}")
        elif routing_data.status == "ok" and routing_data.data:
            route_count = len(routing_data.data)

        # Get platform
        platform = analyzer._get_device_platform(device)

        # Create snapshot
        snapshot = DeviceSnapshot(
            snapshot_id=snapshot_id,
            device=device,
            timestamp=timestamp,
            ospf_neighbors=ospf_neighbors,
            bgp_peers=bgp_peers,
            interfaces=[],  # Interface list collected separately if needed
            route_count=route_count,
            platform=platform,
            notes=notes,
        )

        # Save to database
        self._save_snapshot(snapshot)

        logger.info(
            f"Captured snapshot {snapshot_id} for {device}: "
            f"{len(ospf_neighbors)} OSPF, {len(bgp_peers)} BGP, {route_count} routes"
        )

        return snapshot

    def _save_snapshot(self, snapshot: DeviceSnapshot):
        """Save snapshot to database."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO snapshots
                (snapshot_id, device, timestamp, ospf_neighbors, bgp_peers,
                 interfaces, route_count, platform, is_baseline, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot.snapshot_id,
                snapshot.device,
                snapshot.timestamp,
                json.dumps([n.to_dict() for n in snapshot.ospf_neighbors]),
                json.dumps([p.to_dict() for p in snapshot.bgp_peers]),
                json.dumps([i.to_dict() for i in snapshot.interfaces]),
                snapshot.route_count,
                snapshot.platform,
                1 if snapshot.is_baseline else 0,
                snapshot.notes,
            ))
            conn.commit()

    def get_snapshot(self, snapshot_id: str) -> Optional[DeviceSnapshot]:
        """Get a specific snapshot by ID."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM snapshots WHERE snapshot_id = ?",
                (snapshot_id,)
            ).fetchone()

            if not row:
                return None

            return self._row_to_snapshot(row)

    def _row_to_snapshot(self, row: sqlite3.Row) -> DeviceSnapshot:
        """Convert database row to DeviceSnapshot."""
        return DeviceSnapshot(
            snapshot_id=row["snapshot_id"],
            device=row["device"],
            timestamp=row["timestamp"],
            ospf_neighbors=[
                OSPFNeighborSnapshot.from_dict(n)
                for n in json.loads(row["ospf_neighbors"] or "[]")
            ],
            bgp_peers=[
                BGPPeerSnapshot.from_dict(p)
                for p in json.loads(row["bgp_peers"] or "[]")
            ],
            interfaces=[
                InterfaceSnapshot.from_dict(i)
                for i in json.loads(row["interfaces"] or "[]")
            ],
            route_count=row["route_count"] or 0,
            platform=row["platform"] or "cisco_xe",
            is_baseline=bool(row["is_baseline"]),
            notes=row["notes"],
        )

    # =========================================================================
    # Baseline Management
    # =========================================================================

    def set_baseline(
        self,
        device: str,
        snapshot_id: str,
        set_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Set a snapshot as the active baseline for a device.

        Args:
            device: Device name
            snapshot_id: Snapshot ID to use as baseline
            set_by: Who set this baseline (user, scheduled job, etc.)
            reason: Why this baseline was set

        Returns:
            True if successful
        """
        # Verify snapshot exists and belongs to device
        snapshot = self.get_snapshot(snapshot_id)
        if not snapshot:
            raise ValueError(f"Snapshot '{snapshot_id}' not found")
        if snapshot.device != device:
            raise ValueError(f"Snapshot '{snapshot_id}' belongs to {snapshot.device}, not {device}")

        with self._connect() as conn:
            # Update snapshot's is_baseline flag
            conn.execute(
                "UPDATE snapshots SET is_baseline = 0 WHERE device = ?",
                (device,)
            )
            conn.execute(
                "UPDATE snapshots SET is_baseline = 1 WHERE snapshot_id = ?",
                (snapshot_id,)
            )

            # Update baselines table
            conn.execute("""
                INSERT OR REPLACE INTO baselines (device, snapshot_id, set_at, set_by, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (
                device,
                snapshot_id,
                isonow(),
                set_by,
                reason,
            ))
            conn.commit()

        logger.info(f"Set baseline for {device}: snapshot {snapshot_id}")
        return True

    def get_baseline(self, device: str) -> Optional[DeviceSnapshot]:
        """Get the active baseline snapshot for a device."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT s.* FROM snapshots s
                JOIN baselines b ON s.snapshot_id = b.snapshot_id
                WHERE b.device = ?
            """, (device,)).fetchone()

            if not row:
                return None

            return self._row_to_snapshot(row)

    def clear_baseline(self, device: str) -> bool:
        """Clear the baseline for a device."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE snapshots SET is_baseline = 0 WHERE device = ?",
                (device,)
            )
            conn.execute("DELETE FROM baselines WHERE device = ?", (device,))
            conn.commit()

        logger.info(f"Cleared baseline for {device}")
        return True

    # =========================================================================
    # Drift Detection
    # =========================================================================

    async def compare_to_baseline(self, device: str) -> DriftReport:
        """
        Compare current device state to its baseline.

        Args:
            device: Device name

        Returns:
            DriftReport with detected changes
        """
        # Get baseline
        baseline = self.get_baseline(device)
        if not baseline:
            raise ValueError(f"No baseline set for device '{device}'")

        # Capture current state
        current = await self.capture_snapshot(device, notes="Drift comparison")

        # Compare states
        drifts = self._detect_drifts(baseline, current)

        # Count by severity
        critical_count = sum(1 for d in drifts if d.severity == DriftSeverity.CRITICAL)
        warning_count = sum(1 for d in drifts if d.severity == DriftSeverity.WARNING)
        info_count = sum(1 for d in drifts if d.severity == DriftSeverity.INFO)

        # Generate summary
        if not drifts:
            summary = f"No drift detected for {device}. State matches baseline."
        else:
            summary = (
                f"Detected {len(drifts)} changes for {device}: "
                f"{critical_count} critical, {warning_count} warnings, {info_count} info"
            )

        report = DriftReport(
            device=device,
            baseline_timestamp=baseline.timestamp,
            current_timestamp=current.timestamp,
            total_drifts=len(drifts),
            critical_count=critical_count,
            warning_count=warning_count,
            info_count=info_count,
            drifts=drifts,
            summary=summary,
        )

        # Save drifts to history
        for drift in drifts:
            self._save_drift(drift)

        return report

    def _detect_drifts(
        self,
        baseline: DeviceSnapshot,
        current: DeviceSnapshot,
    ) -> list[StateDrift]:
        """Detect all drifts between baseline and current state."""
        drifts = []
        timestamp = isonow()

        # Compare OSPF neighbors
        drifts.extend(self._compare_ospf(baseline, current, timestamp))

        # Compare BGP peers
        drifts.extend(self._compare_bgp(baseline, current, timestamp))

        # Compare route count
        drifts.extend(self._compare_routes(baseline, current, timestamp))

        return drifts

    def _compare_ospf(
        self,
        baseline: DeviceSnapshot,
        current: DeviceSnapshot,
        timestamp: str,
    ) -> list[StateDrift]:
        """Compare OSPF neighbors between baseline and current."""
        drifts = []
        device = baseline.device

        # Index by neighbor_id for easy lookup
        baseline_neighbors = {n.neighbor_id: n for n in baseline.ospf_neighbors}
        current_neighbors = {n.neighbor_id: n for n in current.ospf_neighbors}

        # Check for lost neighbors
        for nid, neighbor in baseline_neighbors.items():
            if nid not in current_neighbors:
                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.OSPF_NEIGHBOR_LOST,
                    severity=DriftSeverity.CRITICAL,
                    description=f"OSPF neighbor {nid} lost on {neighbor.interface}",
                    baseline_value=f"{nid} via {neighbor.interface}",
                    current_value=None,
                    details=neighbor.to_dict(),
                ))

        # Check for new neighbors
        for nid, neighbor in current_neighbors.items():
            if nid not in baseline_neighbors:
                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.OSPF_NEIGHBOR_ADDED,
                    severity=DriftSeverity.INFO,
                    description=f"New OSPF neighbor {nid} on {neighbor.interface}",
                    baseline_value=None,
                    current_value=f"{nid} via {neighbor.interface}",
                    details=neighbor.to_dict(),
                ))

        # Check for state changes
        for nid in set(baseline_neighbors.keys()) & set(current_neighbors.keys()):
            base_n = baseline_neighbors[nid]
            curr_n = current_neighbors[nid]
            if base_n.state != curr_n.state:
                severity = DriftSeverity.WARNING
                if "FULL" in base_n.state and "FULL" not in curr_n.state:
                    severity = DriftSeverity.CRITICAL

                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.OSPF_NEIGHBOR_STATE_CHANGED,
                    severity=severity,
                    description=f"OSPF neighbor {nid} state changed: {base_n.state} -> {curr_n.state}",
                    baseline_value=base_n.state,
                    current_value=curr_n.state,
                    details={"neighbor_id": nid, "interface": curr_n.interface},
                ))

        return drifts

    def _compare_bgp(
        self,
        baseline: DeviceSnapshot,
        current: DeviceSnapshot,
        timestamp: str,
    ) -> list[StateDrift]:
        """Compare BGP peers between baseline and current."""
        drifts = []
        device = baseline.device

        # Index by peer_ip
        baseline_peers = {p.peer_ip: p for p in baseline.bgp_peers}
        current_peers = {p.peer_ip: p for p in current.bgp_peers}

        # Check for lost peers
        for pip, peer in baseline_peers.items():
            if pip not in current_peers:
                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.BGP_PEER_LOST,
                    severity=DriftSeverity.CRITICAL,
                    description=f"BGP peer {pip} (AS{peer.peer_asn}) lost",
                    baseline_value=f"{pip} AS{peer.peer_asn}",
                    current_value=None,
                    details=peer.to_dict(),
                ))

        # Check for new peers
        for pip, peer in current_peers.items():
            if pip not in baseline_peers:
                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.BGP_PEER_ADDED,
                    severity=DriftSeverity.INFO,
                    description=f"New BGP peer {pip} (AS{peer.peer_asn})",
                    baseline_value=None,
                    current_value=f"{pip} AS{peer.peer_asn}",
                    details=peer.to_dict(),
                ))

        # Check for state changes
        for pip in set(baseline_peers.keys()) & set(current_peers.keys()):
            base_p = baseline_peers[pip]
            curr_p = current_peers[pip]
            if base_p.state != curr_p.state:
                severity = DriftSeverity.WARNING
                if base_p.state.lower() == "established" and curr_p.state.lower() != "established":
                    severity = DriftSeverity.CRITICAL

                drifts.append(StateDrift(
                    drift_id=str(uuid.uuid4())[:8],
                    device=device,
                    detected_at=timestamp,
                    drift_type=DriftType.BGP_PEER_STATE_CHANGED,
                    severity=severity,
                    description=f"BGP peer {pip} state changed: {base_p.state} -> {curr_p.state}",
                    baseline_value=base_p.state,
                    current_value=curr_p.state,
                    details={"peer_ip": pip, "peer_asn": curr_p.peer_asn},
                ))

        return drifts

    def _compare_routes(
        self,
        baseline: DeviceSnapshot,
        current: DeviceSnapshot,
        timestamp: str,
    ) -> list[StateDrift]:
        """Compare route counts between baseline and current."""
        drifts = []
        device = baseline.device

        diff = current.route_count - baseline.route_count
        pct_change = (diff / baseline.route_count * 100) if baseline.route_count > 0 else 0

        # Only flag significant changes (>10% or >5 routes)
        if abs(diff) >= 5 or abs(pct_change) >= 10:
            if diff < 0:
                # Routes lost
                severity = DriftSeverity.WARNING if abs(pct_change) < 20 else DriftSeverity.CRITICAL
                desc = f"Route count decreased by {abs(diff)} ({abs(pct_change):.1f}%)"
            else:
                # Routes added
                severity = DriftSeverity.INFO
                desc = f"Route count increased by {diff} ({pct_change:.1f}%)"

            drifts.append(StateDrift(
                drift_id=str(uuid.uuid4())[:8],
                device=device,
                detected_at=timestamp,
                drift_type=DriftType.ROUTE_COUNT_CHANGED,
                severity=severity,
                description=desc,
                baseline_value=str(baseline.route_count),
                current_value=str(current.route_count),
                details={"difference": diff, "percent_change": pct_change},
            ))

        return drifts

    def _save_drift(self, drift: StateDrift, source: str = "snapshot"):
        """Save drift to history."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO drift_history
                (drift_id, device, detected_at, drift_type, severity,
                 description, baseline_value, current_value, details, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                drift.drift_id,
                drift.device,
                drift.detected_at,
                drift.drift_type.value,
                drift.severity.value,
                drift.description,
                drift.baseline_value,
                drift.current_value,
                json.dumps(drift.details),
                source,
            ))
            conn.commit()

    # =========================================================================
    # History Queries
    # =========================================================================

    def get_snapshots(
        self,
        device: str,
        days: int = 7,
        limit: int = 100,
    ) -> list[DeviceSnapshot]:
        """Get historical snapshots for a device."""
        cutoff = (now() - timedelta(days=days)).isoformat()

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM snapshots
                WHERE device = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (device, cutoff, limit)).fetchall()

            return [self._row_to_snapshot(row) for row in rows]

    def get_drift_history(
        self,
        device: str = None,
        days: int = 7,
        severity: str = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get drift history."""
        cutoff = (now() - timedelta(days=days)).isoformat()

        query = "SELECT * FROM drift_history WHERE detected_at >= ?"
        params = [cutoff]

        if device:
            query += " AND device = ?"
            params.append(device)

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_trending_summary(self, device: str, days: int = 7) -> dict:
        """Get a summary of trending data for a device."""
        cutoff = (now() - timedelta(days=days)).isoformat()

        with self._connect() as conn:
            # Get snapshot count
            snapshot_count = conn.execute("""
                SELECT COUNT(*) FROM snapshots
                WHERE device = ? AND timestamp >= ?
            """, (device, cutoff)).fetchone()[0]

            # Get drift counts by severity
            drift_counts = conn.execute("""
                SELECT severity, COUNT(*) as count FROM drift_history
                WHERE device = ? AND detected_at >= ?
                GROUP BY severity
            """, (device, cutoff)).fetchall()

            # Get baseline info
            baseline = self.get_baseline(device)

            # Get most recent snapshot
            latest = conn.execute("""
                SELECT timestamp, ospf_neighbors, bgp_peers, route_count
                FROM snapshots
                WHERE device = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (device,)).fetchone()

        drift_summary = {row[0]: row[1] for row in drift_counts}

        return {
            "device": device,
            "period_days": days,
            "snapshot_count": snapshot_count,
            "has_baseline": baseline is not None,
            "baseline_timestamp": baseline.timestamp if baseline else None,
            "drift_counts": {
                "critical": drift_summary.get("critical", 0),
                "warning": drift_summary.get("warning", 0),
                "info": drift_summary.get("info", 0),
            },
            "latest_state": {
                "timestamp": latest[0] if latest else None,
                "ospf_neighbor_count": len(json.loads(latest[1] or "[]")) if latest else 0,
                "bgp_peer_count": len(json.loads(latest[2] or "[]")) if latest else 0,
                "route_count": latest[3] if latest else 0,
            } if latest else None,
        }

    def cleanup_old_data(self, retention_days: int = 30) -> dict:
        """Remove snapshots and drift history older than retention period."""
        cutoff = (now() - timedelta(days=retention_days)).isoformat()

        with self._connect() as conn:
            # Don't delete baselines
            snapshots_deleted = conn.execute("""
                DELETE FROM snapshots
                WHERE timestamp < ? AND is_baseline = 0
            """, (cutoff,)).rowcount

            drifts_deleted = conn.execute("""
                DELETE FROM drift_history
                WHERE detected_at < ?
            """, (cutoff,)).rowcount

            conn.commit()

        logger.info(
            f"Cleanup: removed {snapshots_deleted} snapshots, {drifts_deleted} drift records"
        )

        return {
            "snapshots_deleted": snapshots_deleted,
            "drifts_deleted": drifts_deleted,
            "retention_days": retention_days,
        }

    # =========================================================================
    # Drift with Impact Analysis
    # =========================================================================

    async def drift_with_impact(self, device: str) -> dict:
        """
        Run drift check and trace downstream impact via dependency graph.

        1. Compare current state to baseline
        2. For significant drifts, load dependency graph
        3. Trace forward impact for each lost adjacency/peer
        4. Record correlated events
        5. Return combined report

        Args:
            device: Device name

        Returns:
            Dict with drift report + downstream impact analysis
        """
        report = await self.compare_to_baseline(device)

        result = {
            "drift_report": report.to_dict(),
            "downstream_impact": [],
            "correlated_events": [],
        }

        impactful_drift_types = {
            DriftType.OSPF_NEIGHBOR_LOST,
            DriftType.BGP_PEER_LOST,
            DriftType.INTERFACE_DOWN,
        }

        impactful_drifts = [
            d for d in report.drifts if d.drift_type in impactful_drift_types
        ]

        if not impactful_drifts:
            result["summary"] = report.summary
            return result

        try:
            from core.dependency_graph import NetworkDependencyGraph

            graph = NetworkDependencyGraph(db=self.db)
            if not graph.load_latest():
                await graph.build()

            for drift in impactful_drifts:
                impact = graph.forward_impact(device)
                result["downstream_impact"].append({
                    "drift": drift.to_dict(),
                    "affected_devices": impact.get("affected_devices", []),
                    "affected_services": impact.get("affected_services", []),
                    "blast_radius": impact.get("total_affected", 0),
                })

                event_id = str(uuid.uuid4())[:8]
                try:
                    with self._connect() as conn:
                        conn.execute("""
                            INSERT INTO events
                            (event_id, timestamp, subsystem, device, event_type,
                             severity, summary, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            event_id,
                            drift.detected_at,
                            "drift",
                            device,
                            drift.drift_type.value,
                            drift.severity.value,
                            f"{drift.description} (impact: {impact.get('total_affected', 0)} downstream)",
                            json.dumps({
                                "drift": drift.to_dict(),
                                "downstream": impact,
                            }),
                        ))
                        conn.commit()
                    result["correlated_events"].append(event_id)
                except Exception as e:
                    logger.warning(f"Failed to record event: {e}")

        except ImportError:
            logger.warning("Dependency graph module not available")
            result["downstream_impact"] = [
                {"note": "Dependency graph not available for impact tracing"}
            ]
        except Exception as e:
            logger.warning(f"Dependency graph analysis failed: {e}")
            result["downstream_impact"] = [{"error": str(e)}]

        total_affected = sum(
            i.get("blast_radius", 0) for i in result["downstream_impact"]
            if isinstance(i, dict) and "blast_radius" in i
        )
        result["summary"] = (
            f"{report.summary} | "
            f"{len(impactful_drifts)} impactful drifts, "
            f"{total_affected} downstream devices potentially affected"
        )

        return result


# =============================================================================
# Global Instance
# =============================================================================

_trending: Optional[ImpactTrending] = None


def get_impact_trending() -> ImpactTrending:
    """Get the global ImpactTrending instance."""
    global _trending
    if _trending is None:
        _trending = ImpactTrending()
    return _trending
