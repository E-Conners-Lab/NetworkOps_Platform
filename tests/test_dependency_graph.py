"""Tests for core/dependency_graph.py - Network dependency graph."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import networkx as nx

from core.unified_db import UnifiedDB
from core.dependency_graph import NetworkDependencyGraph


def _mock_discover_topology(telemetry_data=None):
    """Mock for discover_topology that returns test data."""
    return {
        "nodes": [
            {"id": "R1", "platform": "cisco_xe", "status": "healthy", "group": "router"},
            {"id": "R2", "platform": "cisco_xe", "status": "healthy", "group": "router"},
            {"id": "R3", "platform": "cisco_xe", "status": "healthy", "group": "router"},
            {"id": "edge1", "platform": "frr", "status": "healthy", "group": "containerlab"},
            {"id": "server1", "platform": "linux", "status": "healthy", "group": "containerlab"},
        ],
        "links": [
            {"source": "R1", "target": "R2", "source_intf": "Gi2", "target_intf": "Gi2"},
            {"source": "R2", "target": "R3", "source_intf": "Gi3", "target_intf": "Gi3"},
            {"source": "R3", "target": "edge1", "source_intf": "Gi4", "target_intf": "eth0"},
            {"source": "edge1", "target": "server1", "source_intf": "eth1", "target_intf": "eth0"},
        ],
        "bgp_links": [
            {"source": "R3", "target": "edge1", "session_type": "ebgp", "state": "Established"},
        ],
    }


@pytest.fixture
def tmp_db(consolidated_db):
    """Create a UnifiedDB backed by the consolidated test DB."""
    db = UnifiedDB.get_instance()
    yield db


class TestGraphBuild:
    """Tests for building the dependency graph."""

    @pytest.mark.asyncio
    async def test_build_from_topology(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)

        with patch("core.topology_helpers.discover_topology", side_effect=_mock_discover_topology):
            await graph.build()

        assert "R1" in graph.graph
        assert "R3" in graph.graph
        assert "edge1" in graph.graph

    @pytest.mark.asyncio
    async def test_physical_links_bidirectional(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)

        with patch("core.topology_helpers.discover_topology", side_effect=_mock_discover_topology):
            await graph.build()

        assert graph.graph.has_edge("R1", "R2")
        assert graph.graph.has_edge("R2", "R1")

    @pytest.mark.asyncio
    async def test_interface_nodes_created(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)

        with patch("core.topology_helpers.discover_topology", side_effect=_mock_discover_topology):
            await graph.build()

        assert "R1:Gi2" in graph.graph
        assert "R3:Gi4" in graph.graph

    @pytest.mark.asyncio
    async def test_bgp_edges_added(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)

        with patch("core.topology_helpers.discover_topology", side_effect=_mock_discover_topology):
            await graph.build()

        assert graph.graph.has_edge("R3", "edge1")

    @pytest.mark.asyncio
    async def test_graph_saved_to_db(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)

        with patch("core.topology_helpers.discover_topology", side_effect=_mock_discover_topology):
            await graph.build()

        with tmp_db.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM dependency_graph"
            ).fetchone()[0]
            assert count == 1


class TestForwardImpact:
    """Tests for forward impact analysis."""

    def test_forward_impact_leaf_device(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R1", node_type="device")
        graph.graph.add_node("R2", node_type="device")
        graph.graph.add_node("R3", node_type="device")
        graph.graph.add_edge("R1", "R2", edge_type="physical_link")
        graph.graph.add_edge("R2", "R3", edge_type="physical_link")

        result = graph.forward_impact("R1")
        assert "R2" in result["affected_devices"]
        assert "R3" in result["affected_devices"]
        assert result["total_affected"] == 2

    def test_forward_impact_unknown_device(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()

        result = graph.forward_impact("UNKNOWN")
        assert result["total_affected"] == 0
        assert "error" in result

    def test_forward_impact_no_downstream(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R1", node_type="device")

        result = graph.forward_impact("R1")
        assert result["total_affected"] == 0
        assert result["affected_devices"] == []


class TestBackwardDependencies:
    """Tests for backward dependency analysis."""

    def test_backward_dependencies(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R1", node_type="device")
        graph.graph.add_node("R2", node_type="device")
        graph.graph.add_node("R3", node_type="device")
        graph.graph.add_edge("R1", "R2", edge_type="physical_link")
        graph.graph.add_edge("R2", "R3", edge_type="physical_link")

        result = graph.backward_dependencies("R3")
        assert "R1" in result["dependencies"]
        assert "R2" in result["dependencies"]
        assert result["total_dependencies"] == 2

    def test_backward_unknown_device(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()

        result = graph.backward_dependencies("UNKNOWN")
        assert result["total_dependencies"] == 0


class TestBlastRadius:
    """Tests for interface-level blast radius."""

    def test_blast_radius_through_interface(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()

        graph.graph.add_node("R3", node_type="device")
        graph.graph.add_node("R3:Gi4", node_type="interface", device="R3")
        graph.graph.add_node("edge1", node_type="device")

        graph.graph.add_edge("R3", "R3:Gi4", edge_type="has_interface")
        graph.graph.add_edge("R3:Gi4", "edge1", edge_type="physical_link")

        result = graph.blast_radius("R3", "Gi4")
        assert "edge1" in result["affected_devices"]
        assert result["total_affected"] == 1

    def test_blast_radius_interface_not_in_graph(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R3", node_type="device")

        result = graph.blast_radius("R3", "NonexistentIntf")
        assert "note" in result


class TestPersistence:
    """Tests for save/load."""

    def test_save_and_load(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R1", node_type="device")
        graph.graph.add_node("R2", node_type="device")
        graph.graph.add_edge("R1", "R2", edge_type="physical_link")

        graph.save()

        # Load into new instance
        graph2 = NetworkDependencyGraph(db=tmp_db)
        loaded = graph2.load_latest()

        assert loaded is True
        assert "R1" in graph2.graph
        assert "R2" in graph2.graph
        assert graph2.graph.has_edge("R1", "R2")

    def test_load_latest_empty_db(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        assert graph.load_latest() is False


class TestToDict:
    """Tests for graph summary export."""

    def test_to_dict(self, tmp_db):
        graph = NetworkDependencyGraph(db=tmp_db)
        graph.graph = nx.DiGraph()
        graph.graph.add_node("R1", node_type="device")
        graph.graph.add_node("R1:Gi1", node_type="interface", device="R1")
        graph.graph.add_edge("R1", "R1:Gi1", edge_type="has_interface")

        summary = graph.to_dict()
        assert summary["node_count"] == 2
        assert summary["edge_count"] == 1
        assert summary["device_count"] == 1
        assert "R1" in summary["devices"]
