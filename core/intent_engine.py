"""
Intent-Based Validation Engine.

Validates live network state against declarative YAML intents.
Unlike snapshot-based drift detection (which compares current vs previous state),
intent validation compares current state against desired/expected state.

Usage:
    from core.intent_engine import IntentEngine, get_intent_engine

    engine = get_intent_engine()
    result = await engine.validate_device("R3")
    # result.violations, result.resolved_count
"""

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from core.timestamps import isonow
from pathlib import Path
from typing import Optional

import yaml

from core.unified_db import UnifiedDB

logger = logging.getLogger(__name__)

DEFAULT_INTENTS_DIR = Path(__file__).parent.parent / "data" / "intents"


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class IntentItem:
    """A single intent expectation."""
    key: str  # neighbor_id, peer_ip, interface name, prefix
    expected_state: str
    severity: str = "warning"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntentDefinition:
    """Complete intent definition for a device."""
    device: str
    role: str
    ospf_neighbors: list[IntentItem] = field(default_factory=list)
    bgp_peers: list[IntentItem] = field(default_factory=list)
    interfaces: list[IntentItem] = field(default_factory=list)
    routes: list[IntentItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "role": self.role,
            "ospf_neighbors": [i.to_dict() for i in self.ospf_neighbors],
            "bgp_peers": [i.to_dict() for i in self.bgp_peers],
            "interfaces": [i.to_dict() for i in self.interfaces],
            "routes": [i.to_dict() for i in self.routes],
        }


@dataclass
class IntentViolation:
    """A detected violation of declared intent."""
    device: str
    intent_type: str  # 'bgp_peer', 'ospf_neighbor', 'interface', 'route'
    intent_key: str
    expected_state: str
    actual_state: Optional[str]
    violation_severity: str
    detected_at: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntentCheck:
    """Result of checking a single intent item (pass or fail)."""
    intent_type: str  # 'ospf_neighbor', 'bgp_peer', 'interface', 'route'
    intent_key: str
    expected_state: str
    actual_state: str
    passed: bool
    severity: str = "info"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationResult:
    """Result of a device validation run."""
    violations: list[IntentViolation] = field(default_factory=list)
    checks: list[IntentCheck] = field(default_factory=list)
    resolved_count: int = 0


# =============================================================================
# Intent Engine
# =============================================================================


class IntentEngine:
    """
    Loads YAML intents, merges role + overrides, and validates live state.
    """

    def __init__(
        self,
        intents_dir: Path = None,
        db: UnifiedDB = None,
    ):
        self.intents_dir = intents_dir or DEFAULT_INTENTS_DIR
        self.db = db or UnifiedDB.get_instance()
        self._intents: dict[str, IntentDefinition] = {}
        self._loaded = False
        self._analyzer = None  # Cached ImpactAnalyzer instance

    def load_intents(self) -> dict[str, IntentDefinition]:
        """Load all intent definitions from YAML files."""
        self._intents = {}

        roles_dir = self.intents_dir / "roles"
        overrides_dir = self.intents_dir / "overrides"

        # Load role templates
        role_map: dict[str, dict] = {}  # device -> role data
        if roles_dir.exists():
            for role_file in sorted(roles_dir.glob("*.yaml")):
                try:
                    with open(role_file) as f:
                        data = yaml.safe_load(f)

                    if not data:
                        continue

                    role_name = data.get("role", role_file.stem)
                    applies_to = data.get("applies_to", [])
                    intent_data = data.get("intent", {})

                    for device_name in applies_to:
                        role_map[device_name] = {
                            "role": role_name,
                            "intent": intent_data,
                        }

                except Exception as e:
                    logger.error(f"Failed to load role file {role_file}: {e}")

        # Load device overrides and merge
        override_map: dict[str, dict] = {}
        if overrides_dir.exists():
            for override_file in sorted(overrides_dir.glob("*.yaml")):
                try:
                    with open(override_file) as f:
                        data = yaml.safe_load(f)

                    if not data:
                        continue

                    device_name = data.get("device", override_file.stem)
                    override_map[device_name] = data.get("intent", {})

                except Exception as e:
                    logger.error(f"Failed to load override file {override_file}: {e}")

        # Build IntentDefinition for each device
        all_devices = set(role_map.keys()) | set(override_map.keys())
        for device_name in all_devices:
            role_data = role_map.get(device_name, {})
            role_intent = role_data.get("intent", {})
            override_intent = override_map.get(device_name, {})
            role_name = role_data.get("role", "custom")

            merged = self._merge_intents(role_intent, override_intent)
            definition = self._build_definition(device_name, role_name, merged)
            self._intents[device_name] = definition

        self._loaded = True
        logger.info(f"Loaded intents for {len(self._intents)} devices")
        return self._intents

    def _merge_intents(self, role_intent: dict, override_intent: dict) -> dict:
        """Merge role intent with device override. Override wins by key field."""
        merged = {}

        for section in ("ospf_neighbors", "bgp_peers", "interfaces", "routes"):
            role_items = role_intent.get(section, []) or []
            override_items = override_intent.get(section, []) or []

            # Determine key field for this section
            key_field = self._get_key_field(section)

            # Index role items by key
            role_by_key = {}
            for item in role_items:
                k = item.get(key_field, "")
                if k:
                    role_by_key[k] = item

            # Override items replace role items by key; unmatched are appended
            for item in override_items:
                k = item.get(key_field, "")
                if k:
                    role_by_key[k] = item

            merged[section] = list(role_by_key.values())

        return merged

    def _get_key_field(self, section: str) -> str:
        """Get the key field for intent matching."""
        return {
            "ospf_neighbors": "neighbor_id",
            "bgp_peers": "peer_ip",
            "interfaces": "name",
            "routes": "prefix",
        }.get(section, "name")

    def _build_definition(
        self, device: str, role: str, merged: dict
    ) -> IntentDefinition:
        """Build IntentDefinition from merged dict."""
        ospf = []
        for item in merged.get("ospf_neighbors", []):
            ospf.append(IntentItem(
                key=item.get("neighbor_id", ""),
                expected_state=item.get("expected_state", "FULL"),
                severity=item.get("severity", "warning"),
                extra=item,
            ))

        bgp = []
        for item in merged.get("bgp_peers", []):
            bgp.append(IntentItem(
                key=item.get("peer_ip", ""),
                expected_state=item.get("expected_state", "Established"),
                severity=item.get("severity", "warning"),
                extra=item,
            ))

        interfaces = []
        for item in merged.get("interfaces", []):
            interfaces.append(IntentItem(
                key=item.get("name", ""),
                expected_state=item.get("expected_status", "up"),
                severity=item.get("severity", "warning"),
                extra=item,
            ))

        routes = []
        for item in merged.get("routes", []):
            routes.append(IntentItem(
                key=item.get("prefix", ""),
                expected_state=item.get("expected_via", ""),
                severity=item.get("severity", "warning"),
                extra=item,
            ))

        return IntentDefinition(
            device=device,
            role=role,
            ospf_neighbors=ospf,
            bgp_peers=bgp,
            interfaces=interfaces,
            routes=routes,
        )

    def get_device_intent(self, device: str) -> Optional[IntentDefinition]:
        """Get intent definition for a specific device."""
        if not self._loaded:
            self.load_intents()
        return self._intents.get(device)

    async def validate_device(self, device: str) -> ValidationResult:
        """
        Validate a device against its declared intent.

        Collects live state and compares against YAML expectations.
        Stores violations in the database. Auto-resolves cleared violations.
        """
        if not self._loaded:
            self.load_intents()

        intent = self._intents.get(device)
        if not intent:
            logger.warning(f"No intent defined for device '{device}'")
            return ValidationResult()

        violations = []
        checks = []
        timestamp = isonow()

        # Collect live state using ImpactAnalyzer's data collection
        live_state = await self._collect_live_state(device)

        # Validate OSPF neighbors
        v, c = self._validate_ospf(device, intent, live_state, timestamp)
        violations.extend(v)
        checks.extend(c)

        # Validate BGP peers
        v, c = self._validate_bgp(device, intent, live_state, timestamp)
        violations.extend(v)
        checks.extend(c)

        # Validate interfaces
        v, c = self._validate_interfaces(device, intent, live_state, timestamp)
        violations.extend(v)
        checks.extend(c)

        # Validate routes
        v, c = self._validate_routes(device, intent, live_state, timestamp)
        violations.extend(v)
        checks.extend(c)

        # Store violations
        for vi in violations:
            self._store_violation(vi)
            self._store_event(vi)

        # Auto-resolve cleared violations
        resolved_count = self._resolve_cleared_violations(device, violations)

        logger.info(
            f"Intent validation for {device}: "
            f"{len(checks)} items checked, {len(violations)} violations found, "
            f"{resolved_count} resolved"
        )

        return ValidationResult(
            violations=violations, checks=checks, resolved_count=resolved_count
        )

    async def validate_all(self) -> dict[str, ValidationResult]:
        """Validate all devices with defined intents."""
        if not self._loaded:
            self.load_intents()

        results = {}
        for device in self._intents:
            try:
                result = await self.validate_device(device)
                results[device] = result
            except Exception as e:
                logger.error(f"Validation failed for {device}: {e}")
                results[device] = ValidationResult(violations=[IntentViolation(
                    device=device,
                    intent_type="error",
                    intent_key="validation",
                    expected_state="success",
                    actual_state=str(e),
                    violation_severity="critical",
                    detected_at=isonow(),
                    details={"error": str(e)},
                )])

        return results

    def _get_analyzer(self):
        """Get or create a cached ImpactAnalyzer instance."""
        if self._analyzer is None:
            from core.impact_analyzer import ImpactAnalyzer
            self._analyzer = ImpactAnalyzer()
        return self._analyzer

    async def _collect_live_state(self, device: str) -> dict:
        """Collect live network state for validation."""
        analyzer = self._get_analyzer()
        state = {
            "ospf_neighbors": {},
            "bgp_peers": {},
            "interfaces": {},
            "routes": {},
        }

        try:
            ospf_task = analyzer._collect_ospf_neighbors(device)
            bgp_task = analyzer._collect_bgp_peers(device)
            route_task = analyzer._collect_routing_table(device)
            intf_task = self._collect_all_interfaces(device)

            ospf_data, bgp_data, route_data, intf_data = await asyncio.gather(
                ospf_task, bgp_task, route_task, intf_task,
                return_exceptions=True,
            )

            # Parse OSPF
            if not isinstance(ospf_data, Exception) and ospf_data.status == "ok":
                for n in (ospf_data.data or []):
                    nid = n.get("neighbor_id", "")
                    if nid:
                        state["ospf_neighbors"][nid] = n.get("state", "")

            # Parse BGP
            if not isinstance(bgp_data, Exception) and bgp_data.status == "ok":
                peers_list = bgp_data.data
                if isinstance(bgp_data.data, dict):
                    peers_list = bgp_data.data.get("peers", [])
                for p in (peers_list or []):
                    if not isinstance(p, dict):
                        continue
                    pip = p.get("neighbor") or p.get("peer_ip", "")
                    if pip:
                        state["bgp_peers"][pip] = p.get("state", "")

            # Parse routes: {prefix: [protocol1, protocol2, ...]}
            if not isinstance(route_data, Exception) and route_data.status == "ok":
                for r in (route_data.data or []):
                    prefix = r.get("prefix", "")
                    protocol = r.get("protocol", "")
                    if prefix and protocol:
                        state["routes"].setdefault(prefix, [])
                        if protocol not in state["routes"][prefix]:
                            state["routes"][prefix].append(protocol)

            # Parse interfaces
            if not isinstance(intf_data, Exception) and isinstance(intf_data, dict):
                state["interfaces"] = intf_data

        except Exception as e:
            logger.warning(f"Failed to collect live state for {device}: {e}")

        return state

    async def _collect_all_interfaces(self, device: str) -> dict:
        """Collect interface status for a device.

        Returns:
            Dict of {interface_name: "up"|"down"}
        """
        analyzer = self._get_analyzer()
        platform = analyzer._get_device_platform(device)

        try:
            if platform in ("srlinux", "frr"):
                cmd = "show interface brief"
            else:
                cmd = "show ip interface brief"

            if analyzer._is_containerlab_device(device):
                from core.containerlab import get_containerlab_command_output
                output = await get_containerlab_command_output(device, cmd)
            else:
                conn = await analyzer._get_readonly_connection(device)
                cmd = analyzer._wrap_command_for_platform(device, cmd)
                async with conn:
                    response = await conn.send_command(cmd)
                    output = response.result

            return self._parse_interface_brief(output, platform)

        except Exception as e:
            logger.warning(f"Failed to collect interfaces for {device}: {e}")
            return {}

    @staticmethod
    def _parse_interface_brief(output: str, platform: str = "cisco_xe") -> dict:
        """Parse interface brief output into {name: 'up'|'down'}.

        Cisco: both status AND protocol must be 'up' for 'up'.
        FRR: interface up/down from tabular output.
        SR Linux: best-effort parse of pipe-delimited table.
        """
        interfaces = {}
        lines = output.strip().split("\n")

        if platform == "srlinux":
            for line in lines:
                if "|" not in line or line.startswith("+"):
                    continue
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 3 and parts[0] != "Interface":
                    name = parts[0]
                    admin = parts[1].lower() if len(parts) > 1 else ""
                    oper = parts[2].lower() if len(parts) > 2 else ""
                    if admin == "enable" and oper == "up":
                        interfaces[name] = "up"
                    elif name and "/" in name:
                        interfaces[name] = "down"

        elif platform == "frr":
            # FRR 'show ip interface brief' is tabular:
            # Interface  Status  VRF  Addresses
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    status = parts[1].lower()
                    interfaces[name] = "up" if status == "up" else "down"

        else:
            # Cisco IOS-XE: show ip interface brief
            # Interface  IP-Address  OK?  Method  Status  Protocol
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    name = parts[0]
                    status = parts[4].lower()
                    protocol = parts[5].lower()
                    interfaces[name] = "up" if status == "up" and protocol == "up" else "down"

        return interfaces

    def _validate_ospf(
        self,
        device: str,
        intent: IntentDefinition,
        live: dict,
        timestamp: str,
    ) -> tuple[list[IntentViolation], list[IntentCheck]]:
        """Validate OSPF neighbor intents."""
        violations = []
        checks = []
        live_ospf = live.get("ospf_neighbors", {})

        for item in intent.ospf_neighbors:
            actual = live_ospf.get(item.key)
            if actual is None:
                violations.append(IntentViolation(
                    device=device,
                    intent_type="ospf_neighbor",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state="missing",
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details={"neighbor_id": item.key},
                ))
                checks.append(IntentCheck(
                    intent_type="ospf_neighbor", intent_key=item.key,
                    expected_state=item.expected_state, actual_state="missing",
                    passed=False, severity=item.severity,
                ))
            elif item.expected_state.upper() not in actual.upper():
                violations.append(IntentViolation(
                    device=device,
                    intent_type="ospf_neighbor",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state=actual,
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details={"neighbor_id": item.key},
                ))
                checks.append(IntentCheck(
                    intent_type="ospf_neighbor", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=False, severity=item.severity,
                ))
            else:
                checks.append(IntentCheck(
                    intent_type="ospf_neighbor", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=True, severity=item.severity,
                ))

        return violations, checks

    def _validate_bgp(
        self,
        device: str,
        intent: IntentDefinition,
        live: dict,
        timestamp: str,
    ) -> tuple[list[IntentViolation], list[IntentCheck]]:
        """Validate BGP peer intents."""
        violations = []
        checks = []
        live_bgp = live.get("bgp_peers", {})

        for item in intent.bgp_peers:
            actual = live_bgp.get(item.key)
            if actual is None:
                violations.append(IntentViolation(
                    device=device,
                    intent_type="bgp_peer",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state="missing",
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details=item.extra,
                ))
                checks.append(IntentCheck(
                    intent_type="bgp_peer", intent_key=item.key,
                    expected_state=item.expected_state, actual_state="missing",
                    passed=False, severity=item.severity,
                ))
            elif actual.lower() != item.expected_state.lower():
                violations.append(IntentViolation(
                    device=device,
                    intent_type="bgp_peer",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state=actual,
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details=item.extra,
                ))
                checks.append(IntentCheck(
                    intent_type="bgp_peer", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=False, severity=item.severity,
                ))
            else:
                checks.append(IntentCheck(
                    intent_type="bgp_peer", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=True, severity=item.severity,
                ))

        return violations, checks

    def _validate_interfaces(
        self,
        device: str,
        intent: IntentDefinition,
        live: dict,
        timestamp: str,
    ) -> tuple[list[IntentViolation], list[IntentCheck]]:
        """Validate interface intents."""
        violations = []
        checks = []
        live_intfs = live.get("interfaces", {})

        for item in intent.interfaces:
            actual = live_intfs.get(item.key)
            if actual is None:
                violations.append(IntentViolation(
                    device=device,
                    intent_type="interface",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state="missing",
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details=item.extra,
                ))
                checks.append(IntentCheck(
                    intent_type="interface", intent_key=item.key,
                    expected_state=item.expected_state, actual_state="missing",
                    passed=False, severity=item.severity,
                ))
            elif actual.lower() != item.expected_state.lower():
                violations.append(IntentViolation(
                    device=device,
                    intent_type="interface",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state=actual,
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details=item.extra,
                ))
                checks.append(IntentCheck(
                    intent_type="interface", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=False, severity=item.severity,
                ))
            else:
                checks.append(IntentCheck(
                    intent_type="interface", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual,
                    passed=True, severity=item.severity,
                ))

        return violations, checks

    def _validate_routes(
        self,
        device: str,
        intent: IntentDefinition,
        live: dict,
        timestamp: str,
    ) -> tuple[list[IntentViolation], list[IntentCheck]]:
        """Validate route intents."""
        violations = []
        checks = []
        live_routes = live.get("routes", {})

        for item in intent.routes:
            actual_protocols = live_routes.get(item.key)
            if actual_protocols is None:
                violations.append(IntentViolation(
                    device=device,
                    intent_type="route",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state="missing",
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details=item.extra,
                ))
                checks.append(IntentCheck(
                    intent_type="route", intent_key=item.key,
                    expected_state=item.expected_state, actual_state="missing",
                    passed=False, severity=item.severity,
                ))
            elif item.expected_state and not any(
                p.lower() == item.expected_state.lower()
                or p.lower().startswith(item.expected_state.lower() + "-")
                for p in actual_protocols
            ):
                actual_str = ", ".join(actual_protocols)
                violations.append(IntentViolation(
                    device=device,
                    intent_type="route",
                    intent_key=item.key,
                    expected_state=item.expected_state,
                    actual_state=actual_str,
                    violation_severity=item.severity,
                    detected_at=timestamp,
                    details={**item.extra, "actual_protocols": actual_protocols},
                ))
                checks.append(IntentCheck(
                    intent_type="route", intent_key=item.key,
                    expected_state=item.expected_state, actual_state=actual_str,
                    passed=False, severity=item.severity,
                ))
            else:
                actual_str = ", ".join(actual_protocols) if actual_protocols else "present"
                checks.append(IntentCheck(
                    intent_type="route", intent_key=item.key,
                    expected_state=item.expected_state or "present",
                    actual_state=actual_str,
                    passed=True, severity=item.severity,
                ))

        return violations, checks

    def _store_violation(self, violation: IntentViolation):
        """Store violation in the database."""
        try:
            with self.db.connect() as conn:
                conn.execute("""
                    INSERT INTO intent_violations
                    (device, intent_type, intent_key, expected_state,
                     actual_state, violation_severity, detected_at, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    violation.device,
                    violation.intent_type,
                    violation.intent_key,
                    violation.expected_state,
                    violation.actual_state,
                    violation.violation_severity,
                    violation.detected_at,
                    json.dumps(violation.details),
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store intent violation: {e}")

    def _store_event(self, violation: IntentViolation):
        """Store an event for cross-subsystem correlation."""
        try:
            event_id = str(uuid.uuid4())[:8]
            with self.db.connect() as conn:
                conn.execute("""
                    INSERT INTO events
                    (event_id, timestamp, subsystem, device, event_type,
                     severity, summary, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id,
                    violation.detected_at,
                    "intent",
                    violation.device,
                    f"intent_{violation.intent_type}_violation",
                    violation.violation_severity,
                    f"Intent violation: {violation.intent_type} "
                    f"'{violation.intent_key}' expected {violation.expected_state}, "
                    f"got {violation.actual_state}",
                    json.dumps(violation.to_dict()),
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store intent event: {e}")

    def _resolve_cleared_violations(
        self,
        device: str,
        current_violations: list[IntentViolation],
    ) -> int:
        """Auto-resolve violations that are no longer present.

        Compares current violation keys against stored unresolved violations.
        Any stored violation whose (intent_type, intent_key) is NOT in the
        current set gets resolved_at = now.

        Returns:
            Count of resolved violations.
        """
        current_keys = {
            (v.intent_type, v.intent_key) for v in current_violations
        }

        try:
            import sqlite3
            with self.db.connect() as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, intent_type, intent_key FROM intent_violations "
                    "WHERE device = ? AND resolved_at IS NULL",
                    (device,),
                ).fetchall()

                now = isonow()
                resolved = 0
                for row in rows:
                    key = (row["intent_type"], row["intent_key"])
                    if key not in current_keys:
                        conn.execute(
                            "UPDATE intent_violations SET resolved_at = ? WHERE id = ?",
                            (now, row["id"]),
                        )
                        resolved += 1

                conn.commit()
                return resolved

        except Exception as e:
            logger.error(f"Failed to resolve violations for {device}: {e}")
            return 0

    def resolve_violation(self, violation_id: int) -> bool:
        """Manually resolve a violation by ID.

        Returns:
            True if resolved, False if not found or already resolved.
        """
        try:
            with self.db.connect() as conn:
                result = conn.execute(
                    "UPDATE intent_violations SET resolved_at = ? "
                    "WHERE id = ? AND resolved_at IS NULL",
                    (isonow(), violation_id),
                )
                conn.commit()
                return result.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to resolve violation {violation_id}: {e}")
            return False

    def get_violations(
        self,
        device: str = None,
        intent_type: str = None,
        unresolved_only: bool = True,
    ) -> list[dict]:
        """Query stored intent violations."""
        query = "SELECT * FROM intent_violations WHERE 1=1"
        params = []

        if device:
            query += " AND device = ?"
            params.append(device)

        if intent_type:
            query += " AND intent_type = ?"
            params.append(intent_type)

        if unresolved_only:
            query += " AND resolved_at IS NULL"

        query += " ORDER BY detected_at DESC"

        with self.db.connect() as conn:
            conn.row_factory = __import__("sqlite3").Row
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    # =========================================================================
    # Discovery
    # =========================================================================

    async def discover_intents(
        self,
        device: str,
        include_routes: bool = True,
        include_interfaces: bool = True,
    ) -> dict:
        """Generate intent YAML from a device's current live state.

        Filters:
        - OSPF: only FULL neighbors → severity: critical
        - BGP: only Established peers → severity: critical
        - Interfaces: only admin up with IP addresses → severity: warning
        - Routes: exclude connected/local/kernel → severity: warning
        """
        live_state = await self._collect_live_state(device)

        intent = {"device": device, "intent": {}}

        # OSPF: only FULL state
        ospf_items = []
        for nid, state in live_state.get("ospf_neighbors", {}).items():
            if "FULL" in state.upper():
                ospf_items.append({
                    "neighbor_id": nid,
                    "expected_state": "FULL",
                    "severity": "critical",
                })
        if ospf_items:
            intent["intent"]["ospf_neighbors"] = ospf_items

        # BGP: only Established
        bgp_items = []
        for peer_ip, state in live_state.get("bgp_peers", {}).items():
            if state.lower() == "established":
                bgp_items.append({
                    "peer_ip": peer_ip,
                    "expected_state": "Established",
                    "severity": "critical",
                })
        if bgp_items:
            intent["intent"]["bgp_peers"] = bgp_items

        # Interfaces: only admin up (skip unassigned/down)
        if include_interfaces:
            intf_items = []
            for name, status in live_state.get("interfaces", {}).items():
                if status == "up":
                    intf_items.append({
                        "name": name,
                        "expected_status": "up",
                        "severity": "warning",
                    })
            if intf_items:
                intent["intent"]["interfaces"] = intf_items

        # Routes: exclude connected/local/kernel
        if include_routes:
            excluded = {"connected", "local", "kernel"}
            route_items = []
            for prefix, protocols in live_state.get("routes", {}).items():
                learned = [p for p in protocols if p.lower() not in excluded]
                if learned:
                    route_items.append({
                        "prefix": prefix,
                        "expected_via": learned[0],
                        "severity": "warning",
                    })
            if route_items:
                intent["intent"]["routes"] = route_items

        return intent

    @staticmethod
    def discover_intents_yaml(intent_dict: dict) -> str:
        """Serialize a discovered intent dict to YAML string."""
        return yaml.dump(intent_dict, default_flow_style=False, sort_keys=False)

    # =========================================================================
    # Health Score
    # =========================================================================

    @staticmethod
    def _calculate_score(total: int, critical: int, warning: int) -> float:
        """Calculate health score. Critical violations count 2x."""
        if total == 0:
            return 100.0
        penalty = critical * 2 + warning
        return max(0.0, (total - penalty) / total * 100.0)

    def compute_health_score(self, device: str = None) -> dict:
        """Compute intent health score from stored violations.

        Uses stored violations (DB), NOT live data. Run intent_validate_all()
        first for up-to-date results.

        Args:
            device: Specific device, or None for network-wide score.

        Returns:
            Dict with score, violation counts, and per-device breakdown.
        """
        if not self._loaded:
            self.load_intents()

        if device:
            devices = [device] if device in self._intents else []
        else:
            devices = list(self._intents.keys())

        total_items = 0
        total_critical = 0
        total_warning = 0
        per_device = {}

        for dev in devices:
            defn = self._intents.get(dev)
            if not defn:
                continue

            items = (
                len(defn.ospf_neighbors)
                + len(defn.bgp_peers)
                + len(defn.interfaces)
                + len(defn.routes)
            )

            violations = self.get_violations(device=dev, unresolved_only=True)
            crit = sum(1 for v in violations if v.get("violation_severity") == "critical")
            warn = sum(1 for v in violations if v.get("violation_severity") == "warning")

            score = self._calculate_score(items, crit, warn)

            per_device[dev] = {
                "score": round(score, 1),
                "total_items": items,
                "critical_violations": crit,
                "warning_violations": warn,
            }

            total_items += items
            total_critical += crit
            total_warning += warn

        network_score = self._calculate_score(total_items, total_critical, total_warning)

        return {
            "score": round(network_score, 1),
            "total_items": total_items,
            "critical_violations": total_critical,
            "warning_violations": total_warning,
            "devices": per_device,
        }

    # =========================================================================
    # Report
    # =========================================================================

    def generate_report(self) -> dict:
        """Generate a consolidated network intent report.

        Returns timestamp, scores, per-device breakdown, top violations,
        and a summary text string.
        """
        if not self._loaded:
            self.load_intents()

        health = self.compute_health_score()
        per_device = health.get("devices", {})

        # Sort: failing first (lowest score), then alphabetically
        sorted_devices = sorted(
            per_device.items(),
            key=lambda x: (x[1]["score"], x[0]),
        )

        # Devices passing vs failing
        passing = [d for d, info in sorted_devices if info["critical_violations"] == 0 and info["warning_violations"] == 0]
        failing = [d for d, info in sorted_devices if info["critical_violations"] > 0 or info["warning_violations"] > 0]

        # Top 5 critical unresolved violations
        all_violations = self.get_violations(unresolved_only=True)
        critical_violations = [
            v for v in all_violations if v.get("violation_severity") == "critical"
        ][:5]

        total_devices = len(per_device)
        total_violations = health["critical_violations"] + health["warning_violations"]

        summary = (
            f"Network intent compliance: {health['score']}% "
            f"({len(passing)}/{total_devices} devices passing, "
            f"{total_violations} violations)"
        )

        return {
            "timestamp": isonow(),
            "network_score": health["score"],
            "devices_passing": passing,
            "devices_failing": failing,
            "per_device": sorted_devices,
            "top_critical_violations": critical_violations,
            "summary": summary,
            "total_items": health["total_items"],
            "critical_count": health["critical_violations"],
            "warning_count": health["warning_violations"],
        }


# =============================================================================
# Global Instance
# =============================================================================

_engine: Optional[IntentEngine] = None


def get_intent_engine() -> IntentEngine:
    """Get the global IntentEngine instance."""
    global _engine
    if _engine is None:
        _engine = IntentEngine()
    return _engine
