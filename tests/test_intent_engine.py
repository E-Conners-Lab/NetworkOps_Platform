"""Tests for core/intent_engine.py - Intent-based validation engine."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from types import SimpleNamespace

import pytest
import yaml

from core.unified_db import UnifiedDB
from core.intent_engine import (
    IntentEngine,
    IntentDefinition,
    IntentItem,
    IntentViolation,
    ValidationResult,
)


@pytest.fixture
def tmp_db(consolidated_db):
    """Create a UnifiedDB backed by the consolidated test DB."""
    db = UnifiedDB.get_instance()
    yield db


@pytest.fixture
def intents_dir(tmp_path):
    """Create a temporary intents directory with sample YAML files."""
    intents = tmp_path / "intents"
    roles = intents / "roles"
    overrides = intents / "overrides"
    roles.mkdir(parents=True)
    overrides.mkdir(parents=True)

    # Core router role
    role_data = {
        "role": "core-router",
        "description": "OSPF backbone router",
        "applies_to": ["R1", "R2"],
        "intent": {
            "ospf_neighbors": [
                {"neighbor_id": "198.51.100.2", "expected_state": "FULL", "severity": "critical"},
            ],
            "bgp_peers": [],
            "interfaces": [
                {"name": "Loopback0", "expected_status": "up", "severity": "critical"},
            ],
            "routes": [],
        },
    }
    with open(roles / "core-router.yaml", "w") as f:
        yaml.dump(role_data, f)

    # R1 override: add a BGP peer
    override_data = {
        "device": "R1",
        "intent": {
            "bgp_peers": [
                {"peer_ip": "10.0.0.1", "peer_asn": 65001, "expected_state": "Established", "severity": "critical"},
            ],
        },
    }
    with open(overrides / "R1.yaml", "w") as f:
        yaml.dump(override_data, f)

    return intents


def _mock_state(**overrides):
    """Build a mock live state dict with defaults."""
    state = {
        "ospf_neighbors": {},
        "bgp_peers": {},
        "interfaces": {},
        "routes": {},
    }
    state.update(overrides)
    return state


class TestIntentLoading:
    """Tests for YAML loading and merge logic."""

    def test_load_role_intents(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        intents = engine.load_intents()

        assert "R1" in intents
        assert "R2" in intents
        assert intents["R1"].role == "core-router"
        assert intents["R2"].role == "core-router"

    def test_role_ospf_neighbors_loaded(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        intents = engine.load_intents()

        r2 = intents["R2"]
        assert len(r2.ospf_neighbors) == 1
        assert r2.ospf_neighbors[0].key == "198.51.100.2"
        assert r2.ospf_neighbors[0].expected_state == "FULL"

    def test_override_merges_bgp_peer(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        intents = engine.load_intents()

        r1 = intents["R1"]
        assert len(r1.bgp_peers) == 1
        assert r1.bgp_peers[0].key == "10.0.0.1"
        assert r1.bgp_peers[0].severity == "critical"

    def test_override_preserves_role_intents(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        intents = engine.load_intents()

        r1 = intents["R1"]
        # Should still have OSPF neighbors from role
        assert len(r1.ospf_neighbors) == 1

    def test_get_device_intent_loads_on_first_call(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        # Don't call load_intents() manually
        intent = engine.get_device_intent("R1")
        assert intent is not None
        assert intent.device == "R1"

    def test_get_device_intent_returns_none_for_unknown(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        intent = engine.get_device_intent("UNKNOWN_DEVICE")
        assert intent is None

    def test_override_replaces_by_key(self, tmp_path, tmp_db):
        """Override entry with same key field replaces role entry."""
        intents = tmp_path / "intents2"
        roles = intents / "roles"
        overrides = intents / "overrides"
        roles.mkdir(parents=True)
        overrides.mkdir(parents=True)

        role_data = {
            "role": "test",
            "applies_to": ["D1"],
            "intent": {
                "interfaces": [
                    {"name": "eth0", "expected_status": "up", "severity": "warning"},
                ],
            },
        }
        with open(roles / "test.yaml", "w") as f:
            yaml.dump(role_data, f)

        override_data = {
            "device": "D1",
            "intent": {
                "interfaces": [
                    {"name": "eth0", "expected_status": "down", "severity": "critical"},
                ],
            },
        }
        with open(overrides / "D1.yaml", "w") as f:
            yaml.dump(override_data, f)

        engine = IntentEngine(intents_dir=intents, db=tmp_db)
        intents_loaded = engine.load_intents()

        d1 = intents_loaded["D1"]
        assert len(d1.interfaces) == 1
        assert d1.interfaces[0].expected_state == "down"
        assert d1.interfaces[0].severity == "critical"

    def test_empty_intents_dir(self, tmp_path, tmp_db):
        empty_dir = tmp_path / "empty_intents"
        empty_dir.mkdir()
        (empty_dir / "roles").mkdir()
        (empty_dir / "overrides").mkdir()

        engine = IntentEngine(intents_dir=empty_dir, db=tmp_db)
        intents = engine.load_intents()
        assert len(intents) == 0


class TestIntentValidation:
    """Tests for validation with mocked live state."""

    @pytest.mark.asyncio
    async def test_validate_device_no_violations(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Established"},
            interfaces={"Loopback0": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.validate_device("R1")

        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_validate_device_ospf_missing(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state(
            bgp_peers={"10.0.0.1": "Established"},
            interfaces={"Loopback0": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.validate_device("R1")

        ospf = [v for v in result.violations if v.intent_type == "ospf_neighbor"]
        assert len(ospf) == 1
        assert ospf[0].actual_state == "missing"

    @pytest.mark.asyncio
    async def test_validate_device_bgp_wrong_state(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Active"},
            interfaces={"Loopback0": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.validate_device("R1")

        bgp_violations = [v for v in result.violations if v.intent_type == "bgp_peer"]
        assert len(bgp_violations) == 1
        assert bgp_violations[0].expected_state == "Established"
        assert bgp_violations[0].actual_state == "Active"

    @pytest.mark.asyncio
    async def test_validate_stores_to_db(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state()

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            await engine.validate_device("R1")

        # Check violations table
        with tmp_db.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM intent_violations WHERE device='R1'"
            ).fetchone()[0]
            assert count > 0

        # Check events table
        with tmp_db.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE device='R1' AND subsystem='intent'"
            ).fetchone()[0]
            assert count > 0

    @pytest.mark.asyncio
    async def test_validate_unknown_device(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        result = await engine.validate_device("NONEXISTENT")
        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_validate_all(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            interfaces={"Loopback0": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            results = await engine.validate_all()

        assert "R1" in results
        assert "R2" in results
        assert isinstance(results["R1"], ValidationResult)

    @pytest.mark.asyncio
    async def test_validate_returns_validation_result(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        mock_state = _mock_state()

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.validate_device("R1")

        assert isinstance(result, ValidationResult)
        assert isinstance(result.violations, list)
        assert isinstance(result.resolved_count, int)


class TestGetViolations:
    """Tests for violation query."""

    def test_get_violations_empty(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        violations = engine.get_violations(device="R1")
        assert len(violations) == 0

    def test_get_violations_after_insert(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'bgp_peer', '10.0.0.1', 'Established',
                        'Active', 'critical', '2025-01-01')
            """)
            conn.commit()

        violations = engine.get_violations(device="R1")
        assert len(violations) == 1
        assert violations[0]["intent_key"] == "10.0.0.1"


class TestRouteValidation:
    """Tests for route validation (Feature 1)."""

    @pytest.fixture
    def route_engine(self, tmp_path, tmp_db):
        """Engine with route intents defined."""
        intents = tmp_path / "route_intents"
        overrides = intents / "overrides"
        (intents / "roles").mkdir(parents=True)
        overrides.mkdir(parents=True)

        override_data = {
            "device": "R3",
            "intent": {
                "routes": [
                    {"prefix": "10.0.12.0/30", "expected_via": "ospf", "severity": "warning"},
                    {"prefix": "172.16.0.0/24", "expected_via": "bgp", "severity": "critical"},
                ],
            },
        }
        with open(overrides / "R3.yaml", "w") as f:
            yaml.dump(override_data, f)

        engine = IntentEngine(intents_dir=intents, db=tmp_db)
        engine.load_intents()
        return engine

    @pytest.mark.asyncio
    async def test_route_present_correct_protocol(self, route_engine):
        mock_state = _mock_state(routes={
            "10.0.12.0/30": ["ospf"],
            "172.16.0.0/24": ["bgp"],
        })

        with patch.object(route_engine, "_collect_live_state", return_value=mock_state):
            result = await route_engine.validate_device("R3")

        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_route_missing(self, route_engine):
        mock_state = _mock_state(routes={
            "10.0.12.0/30": ["ospf"],
            # 172.16.0.0/24 missing
        })

        with patch.object(route_engine, "_collect_live_state", return_value=mock_state):
            result = await route_engine.validate_device("R3")

        route_v = [v for v in result.violations if v.intent_type == "route"]
        assert len(route_v) == 1
        assert route_v[0].intent_key == "172.16.0.0/24"
        assert route_v[0].actual_state == "missing"

    @pytest.mark.asyncio
    async def test_route_wrong_protocol(self, route_engine):
        mock_state = _mock_state(routes={
            "10.0.12.0/30": ["static"],  # Expected ospf
            "172.16.0.0/24": ["bgp"],
        })

        with patch.object(route_engine, "_collect_live_state", return_value=mock_state):
            result = await route_engine.validate_device("R3")

        route_v = [v for v in result.violations if v.intent_type == "route"]
        assert len(route_v) == 1
        assert route_v[0].intent_key == "10.0.12.0/30"
        assert route_v[0].expected_state == "ospf"
        assert "static" in route_v[0].actual_state

    @pytest.mark.asyncio
    async def test_route_multiple_protocols_ecmp(self, route_engine):
        """Route with multiple protocols (ECMP) should pass if expected is present."""
        mock_state = _mock_state(routes={
            "10.0.12.0/30": ["ospf", "static"],  # Both present — ospf expected
            "172.16.0.0/24": ["bgp"],
        })

        with patch.object(route_engine, "_collect_live_state", return_value=mock_state):
            result = await route_engine.validate_device("R3")

        assert len(result.violations) == 0


class TestInterfaceValidation:
    """Tests for interface live data collection and validation (Feature 2)."""

    @pytest.fixture
    def intf_engine(self, tmp_path, tmp_db):
        """Engine with interface intents defined."""
        intents = tmp_path / "intf_intents"
        overrides = intents / "overrides"
        (intents / "roles").mkdir(parents=True)
        overrides.mkdir(parents=True)

        override_data = {
            "device": "R1",
            "intent": {
                "interfaces": [
                    {"name": "Loopback0", "expected_status": "up", "severity": "critical"},
                    {"name": "GigabitEthernet1", "expected_status": "up", "severity": "warning"},
                ],
            },
        }
        with open(overrides / "R1.yaml", "w") as f:
            yaml.dump(override_data, f)

        engine = IntentEngine(intents_dir=intents, db=tmp_db)
        engine.load_intents()
        return engine

    @pytest.mark.asyncio
    async def test_interface_matches(self, intf_engine):
        mock_state = _mock_state(interfaces={
            "Loopback0": "up",
            "GigabitEthernet1": "up",
        })

        with patch.object(intf_engine, "_collect_live_state", return_value=mock_state):
            result = await intf_engine.validate_device("R1")

        assert len(result.violations) == 0

    @pytest.mark.asyncio
    async def test_interface_down(self, intf_engine):
        mock_state = _mock_state(interfaces={
            "Loopback0": "up",
            "GigabitEthernet1": "down",
        })

        with patch.object(intf_engine, "_collect_live_state", return_value=mock_state):
            result = await intf_engine.validate_device("R1")

        intf_v = [v for v in result.violations if v.intent_type == "interface"]
        assert len(intf_v) == 1
        assert intf_v[0].intent_key == "GigabitEthernet1"
        assert intf_v[0].actual_state == "down"

    @pytest.mark.asyncio
    async def test_interface_missing(self, intf_engine):
        """Missing interface should be flagged as violation."""
        mock_state = _mock_state(interfaces={
            "Loopback0": "up",
            # GigabitEthernet1 missing
        })

        with patch.object(intf_engine, "_collect_live_state", return_value=mock_state):
            result = await intf_engine.validate_device("R1")

        intf_v = [v for v in result.violations if v.intent_type == "interface"]
        assert len(intf_v) == 1
        assert intf_v[0].actual_state == "missing"

    def test_parse_cisco_interface_brief(self):
        """Cisco show ip interface brief parser."""
        output = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       10.0.12.1       YES NVRAM  up                    up
GigabitEthernet2       10.0.13.1       YES NVRAM  up                    down
Loopback0              198.51.100.1    YES NVRAM  up                    up
GigabitEthernet3       unassigned      YES NVRAM  administratively down down"""

        result = IntentEngine._parse_interface_brief(output, "cisco_xe")
        assert result["GigabitEthernet1"] == "up"
        assert result["GigabitEthernet2"] == "down"  # protocol down
        assert result["Loopback0"] == "up"
        assert result["GigabitEthernet3"] == "down"

    def test_parse_frr_interface_brief(self):
        """FRR show ip interface brief parser."""
        output = """Interface       Status  VRF             Addresses
eth0            up      default         10.0.13.2/30
eth1            up      default         10.200.0.1/24
lo              up      default         198.51.100.5/32
eth2            down    default"""

        result = IntentEngine._parse_interface_brief(output, "frr")
        assert result["eth0"] == "up"
        assert result["eth1"] == "up"
        assert result["lo"] == "up"
        assert result["eth2"] == "down"


class TestResolutionTracking:
    """Tests for violation resolution tracking (Feature 4)."""

    @pytest.mark.asyncio
    async def test_auto_resolve_on_fix(self, intents_dir, tmp_db):
        """Violation auto-resolves when re-validation shows it's fixed."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        # First run: BGP is down → creates violation
        bad_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Active"},
            interfaces={"Loopback0": "up"},
        )
        with patch.object(engine, "_collect_live_state", return_value=bad_state):
            result1 = await engine.validate_device("R1")
        assert len(result1.violations) > 0

        # Second run: BGP is fixed → old violation auto-resolved
        good_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Established"},
            interfaces={"Loopback0": "up"},
        )
        with patch.object(engine, "_collect_live_state", return_value=good_state):
            result2 = await engine.validate_device("R1")

        assert result2.resolved_count > 0
        assert len(result2.violations) == 0

    @pytest.mark.asyncio
    async def test_stays_open_when_still_failing(self, intents_dir, tmp_db):
        """Violation stays unresolved when issue persists."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        bad_state = _mock_state(
            ospf_neighbors={"198.51.100.2": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Active"},
            interfaces={"Loopback0": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=bad_state):
            await engine.validate_device("R1")
            result2 = await engine.validate_device("R1")

        # BGP violation should still exist — not resolved
        unresolved = engine.get_violations(device="R1", unresolved_only=True)
        bgp_unresolved = [v for v in unresolved if v["intent_type"] == "bgp_peer"]
        assert len(bgp_unresolved) > 0

    def test_manual_resolve_by_id(self, intents_dir, tmp_db):
        """Manual resolution sets resolved_at."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'bgp_peer', '10.0.0.1', 'Established',
                        'Active', 'critical', '2025-01-01')
            """)
            conn.commit()

        assert engine.resolve_violation(1) is True

        # Should no longer show as unresolved
        violations = engine.get_violations(device="R1", unresolved_only=True)
        assert len(violations) == 0

    def test_resolve_nonexistent_returns_false(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        assert engine.resolve_violation(9999) is False


class TestDiscovery:
    """Tests for intent discovery (Feature 3)."""

    @pytest.mark.asyncio
    async def test_discover_valid_state(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        mock_state = _mock_state(
            ospf_neighbors={"198.51.100.1": "FULL/DR", "198.51.100.2": "2WAY/DR"},
            bgp_peers={"10.0.0.1": "Established", "10.0.0.2": "Idle"},
            interfaces={"Loopback0": "up", "GigabitEthernet1": "down"},
            routes={
                "10.0.12.0/30": ["connected"],
                "172.16.0.0/24": ["bgp"],
                "198.51.100.0/24": ["ospf"],
            },
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.discover_intents("R1")

        intent = result["intent"]

        # Only FULL OSPF neighbors
        assert len(intent["ospf_neighbors"]) == 1
        assert intent["ospf_neighbors"][0]["neighbor_id"] == "198.51.100.1"

        # Only Established BGP peers
        assert len(intent["bgp_peers"]) == 1
        assert intent["bgp_peers"][0]["peer_ip"] == "10.0.0.1"

        # Only up interfaces
        assert len(intent["interfaces"]) == 1
        assert intent["interfaces"][0]["name"] == "Loopback0"

    @pytest.mark.asyncio
    async def test_discover_filters_local_connected_routes(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        mock_state = _mock_state(
            routes={
                "10.0.12.0/30": ["connected"],
                "10.0.12.1/32": ["local"],
                "172.16.0.0/24": ["bgp"],
                "0.0.0.0/0": ["kernel"],
            },
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.discover_intents("R1")

        routes = result["intent"].get("routes", [])
        # Only bgp route should remain
        assert len(routes) == 1
        assert routes[0]["prefix"] == "172.16.0.0/24"

    @pytest.mark.asyncio
    async def test_discover_filters_down_interfaces(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        mock_state = _mock_state(
            interfaces={"eth0": "up", "eth1": "down", "eth2": "up"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.discover_intents("R1")

        intfs = result["intent"].get("interfaces", [])
        names = [i["name"] for i in intfs]
        assert "eth0" in names
        assert "eth2" in names
        assert "eth1" not in names

    @pytest.mark.asyncio
    async def test_discover_yaml_round_trip(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)

        mock_state = _mock_state(
            ospf_neighbors={"198.51.100.1": "FULL/DR"},
            bgp_peers={"10.0.0.1": "Established"},
        )

        with patch.object(engine, "_collect_live_state", return_value=mock_state):
            result = await engine.discover_intents("R1")

        yaml_str = engine.discover_intents_yaml(result)
        parsed = yaml.safe_load(yaml_str)
        assert parsed["device"] == "R1"
        assert "ospf_neighbors" in parsed["intent"]


class TestHealthScore:
    """Tests for intent health score (Feature 5)."""

    def test_perfect_score(self, intents_dir, tmp_db):
        """No violations = 100%."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        health = engine.compute_health_score()
        assert health["score"] == 100.0

    def test_critical_impact_2x(self, intents_dir, tmp_db):
        """Critical violations have 2x penalty."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        # R1 has: 1 ospf_neighbor, 1 bgp_peer, 1 interface = 3 items
        # Insert 1 critical violation
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'bgp_peer', '10.0.0.1', 'Established',
                        'Active', 'critical', '2025-01-01')
            """)
            conn.commit()

        health = engine.compute_health_score(device="R1")
        # 3 items, 1 critical (penalty=2): (3-2)/3 = 33.3%
        assert health["score"] == pytest.approx(33.3, abs=0.1)
        assert health["critical_violations"] == 1

    def test_warning_impact(self, intents_dir, tmp_db):
        """Warning violations have 1x penalty."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'interface', 'Loopback0', 'up',
                        'down', 'warning', '2025-01-01')
            """)
            conn.commit()

        health = engine.compute_health_score(device="R1")
        # 3 items, 1 warning (penalty=1): (3-1)/3 = 66.7%
        assert health["score"] == pytest.approx(66.7, abs=0.1)

    def test_zero_items_equals_100(self, tmp_path, tmp_db):
        """Device with no intent items = 100%."""
        empty_dir = tmp_path / "empty"
        (empty_dir / "roles").mkdir(parents=True)
        (empty_dir / "overrides").mkdir(parents=True)

        engine = IntentEngine(intents_dir=empty_dir, db=tmp_db)
        engine.load_intents()

        health = engine.compute_health_score()
        assert health["score"] == 100.0

    def test_network_wide_aggregation(self, intents_dir, tmp_db):
        """Network-wide score aggregates across devices."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        # Insert violation for R1
        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'bgp_peer', '10.0.0.1', 'Established',
                        'Active', 'warning', '2025-01-01')
            """)
            conn.commit()

        health = engine.compute_health_score()
        # R1: 3 items (ospf, bgp, intf), R2: 2 items (ospf, intf) = 5 total
        # 1 warning penalty = (5-1)/5 = 80%
        assert health["score"] == 80.0
        assert "R1" in health["devices"]
        assert "R2" in health["devices"]


class TestReport:
    """Tests for network intent report (Feature 6)."""

    def test_report_structure(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        report = engine.generate_report()

        assert "timestamp" in report
        assert "network_score" in report
        assert "devices_passing" in report
        assert "devices_failing" in report
        assert "per_device" in report
        assert "top_critical_violations" in report
        assert "summary" in report

    def test_report_failing_first_sort(self, intents_dir, tmp_db):
        """Failing devices should sort before passing."""
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        with tmp_db.connect() as conn:
            conn.execute("""
                INSERT INTO intent_violations
                (device, intent_type, intent_key, expected_state,
                 actual_state, violation_severity, detected_at)
                VALUES ('R1', 'bgp_peer', '10.0.0.1', 'Established',
                        'Active', 'critical', '2025-01-01')
            """)
            conn.commit()

        report = engine.generate_report()

        # R1 should be in failing list
        assert "R1" in report["devices_failing"]
        # R2 should be in passing list
        assert "R2" in report["devices_passing"]

        # per_device sorted by score ascending (failing first)
        device_names = [d[0] for d in report["per_device"]]
        r1_idx = device_names.index("R1")
        r2_idx = device_names.index("R2")
        assert r1_idx < r2_idx

    def test_report_summary_includes_counts(self, intents_dir, tmp_db):
        engine = IntentEngine(intents_dir=intents_dir, db=tmp_db)
        engine.load_intents()

        report = engine.generate_report()

        assert "passing" in report["summary"].lower() or "/" in report["summary"]
        assert "violation" in report["summary"].lower()
