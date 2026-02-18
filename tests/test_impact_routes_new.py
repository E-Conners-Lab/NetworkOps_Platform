"""Tests for new impact routes: intent validation, dependency graph, events."""

import json
import os
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

# Uses app, client, auth_headers fixtures from conftest.py


def _mock_impact_config(enabled=True):
    """Return a mock impact analysis config."""
    return {
        "enabled": enabled,
        "supported_platforms": ["cisco_xe", "frr", "srlinux"],
    }


# =============================================================================
# Intent Validation Route Tests
# =============================================================================


class TestIntentValidateDevice:
    """Tests for GET /api/impact/intent/<device>."""

    def test_returns_501_when_disabled(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config(enabled=False)):
            resp = client.get('/api/impact/intent/R1', headers=auth_headers)
        assert resp.status_code == 501

    def test_returns_404_for_unknown_device(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R1": {}}):
            resp = client.get('/api/impact/intent/FAKE', headers=auth_headers)
        assert resp.status_code == 404

    def test_returns_no_intent_when_not_defined(self, client, auth_headers):
        mock_engine = MagicMock()
        mock_engine.get_device_intent.return_value = None

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R1": {}}), \
             patch("core.intent_engine.get_intent_engine", return_value=mock_engine):
            resp = client.get('/api/impact/intent/R1', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "no_intent"

    def test_returns_violations_on_success(self, client, auth_headers):
        from core.intent_engine import IntentDefinition, IntentItem, IntentViolation, ValidationResult

        mock_intent = IntentDefinition(
            device="R3", role="edge-router",
            bgp_peers=[IntentItem(key="172.20.20.5", expected_state="Established", severity="critical")],
        )

        mock_violation = IntentViolation(
            device="R3", intent_type="bgp_peer", intent_key="172.20.20.5",
            expected_state="Established", actual_state="Active",
            violation_severity="critical", detected_at="2025-01-01T00:00:00",
        )

        mock_engine = MagicMock()
        mock_engine.get_device_intent.return_value = mock_intent

        async def mock_validate(device):
            return ValidationResult(violations=[mock_violation])
        mock_engine.validate_device = mock_validate

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R3": {}}), \
             patch("core.intent_engine.get_intent_engine", return_value=mock_engine):
            resp = client.get('/api/impact/intent/R3', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["total_violations"] == 1
        assert data["critical_count"] == 1
        assert data["violations"][0]["intent_key"] == "172.20.20.5"


class TestIntentValidateAll:
    """Tests for GET /api/impact/intent."""

    def test_returns_501_when_disabled(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config(enabled=False)):
            resp = client.get('/api/impact/intent', headers=auth_headers)
        assert resp.status_code == 501

    def test_returns_results_on_success(self, client, auth_headers):
        from core.intent_engine import ValidationResult
        mock_engine = MagicMock()

        async def mock_validate_all():
            return {"R1": ValidationResult(), "R3": ValidationResult()}
        mock_engine.validate_all = mock_validate_all

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("core.intent_engine.get_intent_engine", return_value=mock_engine):
            resp = client.get('/api/impact/intent', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["devices_checked"] == 2


class TestIntentViolations:
    """Tests for GET /api/impact/intent/<device>/violations."""

    def test_returns_404_for_unknown_device(self, client, auth_headers):
        with patch("config.devices.DEVICES", {"R1": {}}):
            resp = client.get('/api/impact/intent/FAKE/violations', headers=auth_headers)
        assert resp.status_code == 404

    def test_returns_stored_violations(self, client, auth_headers):
        mock_engine = MagicMock()
        mock_engine.get_violations.return_value = [
            {"device": "R3", "intent_type": "bgp_peer", "intent_key": "172.20.20.5"}
        ]

        with patch("config.devices.DEVICES", {"R3": {}}), \
             patch("core.intent_engine.get_intent_engine", return_value=mock_engine):
            resp = client.get('/api/impact/intent/R3/violations', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1


class TestIntentDefinitions:
    """Tests for GET /api/impact/intent/definitions."""

    def test_returns_definitions(self, client, auth_headers):
        from core.intent_engine import IntentDefinition

        mock_engine = MagicMock()
        mock_engine.load_intents.return_value = {
            "R1": IntentDefinition(device="R1", role="core-router"),
        }

        with patch("core.intent_engine.get_intent_engine", return_value=mock_engine):
            resp = client.get('/api/impact/intent/definitions', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert "R1" in data["definitions"]


# =============================================================================
# Dependency Graph Route Tests
# =============================================================================


class TestGraphBuild:
    """Tests for POST /api/impact/graph/build."""

    def test_returns_501_when_disabled(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config(enabled=False)):
            resp = client.post('/api/impact/graph/build', headers=auth_headers)
        assert resp.status_code == 501

    def test_builds_graph_on_success(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.to_dict.return_value = {
            "node_count": 10, "edge_count": 20,
            "device_count": 5, "devices": ["R1", "R2"],
            "edge_types": ["physical_link"],
        }

        async def mock_build():
            return mock_graph.graph
        mock_graph.build = mock_build

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.post('/api/impact/graph/build', headers=auth_headers)

        assert resp.status_code == 201
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["graph"]["node_count"] == 10


class TestGraphGet:
    """Tests for GET /api/impact/graph."""

    def test_returns_not_built_when_empty(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = False

        with patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "not_built"

    def test_returns_graph_when_loaded(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = True
        mock_graph.to_dict.return_value = {"node_count": 5, "edge_count": 8}

        with patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"


class TestForwardImpact:
    """Tests for GET /api/impact/graph/forward/<device>."""

    def test_returns_501_when_disabled(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config(enabled=False)):
            resp = client.get('/api/impact/graph/forward/R1', headers=auth_headers)
        assert resp.status_code == 501

    def test_returns_404_for_unknown_device(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R1": {}}):
            resp = client.get('/api/impact/graph/forward/FAKE', headers=auth_headers)
        assert resp.status_code == 404

    def test_returns_impact_on_success(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = True
        mock_graph.forward_impact.return_value = {
            "device": "R3",
            "affected_devices": ["edge1"],
            "total_affected": 1,
        }

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R3": {}}), \
             patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph/forward/R3', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert data["total_affected"] == 1


class TestBackwardDependencies:
    """Tests for GET /api/impact/graph/backward/<device>."""

    def test_returns_dependencies(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = True
        mock_graph.backward_dependencies.return_value = {
            "device": "edge1",
            "dependencies": ["R1", "R3"],
            "total_dependencies": 2,
        }

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"edge1": {}}), \
             patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph/backward/edge1', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_dependencies"] == 2


class TestBlastRadius:
    """Tests for GET /api/impact/graph/blast-radius/<device>/<interface>."""

    def test_returns_blast_radius(self, client, auth_headers):
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = True
        mock_graph.blast_radius.return_value = {
            "device": "R3",
            "interface": "GigabitEthernet4",
            "affected_devices": ["edge1"],
            "total_affected": 1,
        }

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R3": {}}), \
             patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph/blast-radius/R3/GigabitEthernet4',
                              headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_affected"] == 1
        assert data["interface"] == "GigabitEthernet4"

    def test_handles_interface_with_slash(self, client, auth_headers):
        """SR Linux interfaces have slashes like ethernet-1/1."""
        mock_graph = MagicMock()
        mock_graph.load_latest.return_value = True
        mock_graph.blast_radius.return_value = {
            "device": "spine1",
            "interface": "ethernet-1/1",
            "affected_devices": [],
            "total_affected": 0,
        }

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"spine1": {}}), \
             patch("core.dependency_graph.NetworkDependencyGraph",
                    return_value=mock_graph):
            resp = client.get('/api/impact/graph/blast-radius/spine1/ethernet-1/1',
                              headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["interface"] == "ethernet-1/1"


# =============================================================================
# Events Route Tests
# =============================================================================


class TestEvents:
    """Tests for GET /api/impact/events."""

    def test_returns_empty_events(self, client, auth_headers):
        from core.unified_db import UnifiedDB

        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_db.connect.return_value = mock_conn

        with patch("core.unified_db.UnifiedDB.get_instance", return_value=mock_db):
            resp = client.get('/api/impact/events', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["events"] == []

    def test_accepts_query_params(self, client, auth_headers):
        """Verify query params are accepted without error."""
        from core.unified_db import UnifiedDB

        mock_db = MagicMock()
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_db.connect.return_value = mock_conn

        with patch("core.unified_db.UnifiedDB.get_instance", return_value=mock_db):
            resp = client.get(
                '/api/impact/events?device=R3&subsystem=intent&severity=critical&days=30&limit=50',
                headers=auth_headers
            )

        assert resp.status_code == 200


# =============================================================================
# Drift with Impact Route Test
# =============================================================================


class TestDriftWithImpact:
    """Tests for GET /api/impact/trending/<device>/drift-impact."""

    def test_returns_501_when_disabled(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config(enabled=False)):
            resp = client.get('/api/impact/trending/R1/drift-impact', headers=auth_headers)
        assert resp.status_code == 501

    def test_returns_404_for_unknown_device(self, client, auth_headers):
        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R1": {}}):
            resp = client.get('/api/impact/trending/FAKE/drift-impact', headers=auth_headers)
        assert resp.status_code == 404

    def test_returns_no_baseline_when_missing(self, client, auth_headers):
        mock_trending = MagicMock()
        mock_trending.get_baseline.return_value = None

        with patch("core.feature_flags.get_impact_analysis_config",
                    return_value=_mock_impact_config()), \
             patch("config.devices.DEVICES", {"R1": {}}), \
             patch("core.impact_trending.get_impact_trending",
                    return_value=mock_trending):
            resp = client.get('/api/impact/trending/R1/drift-impact', headers=auth_headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "no_baseline"
