"""
OSPF Network Validation Tests
Tests the MCP lab network for proper OSPF configuration and connectivity.
Requires real network devices — skipped when SKIP_DEVICE_TESTS is set.
"""
import os
import sys
from pathlib import Path

# Add project root to path for shared config imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from netmiko import ConnectHandler

pytestmark = pytest.mark.skipif(
    os.getenv("SKIP_DEVICE_TESTS"), reason="Skipping device tests (SKIP_DEVICE_TESTS is set)"
)

# Shared device configuration (single source of truth)
from config.devices import DEVICES as ALL_DEVICES, USERNAME, PASSWORD

# Filter to only Cisco routers for OSPF tests
DEVICES = {
    name: device for name, device in ALL_DEVICES.items()
    if device.get("device_type") == "cisco_xe" and not name.startswith("Switch")
}

# Expected OSPF neighbors for each router
EXPECTED_NEIGHBORS = {
    "R1": ["198.51.100.2", "198.51.100.3"],
    "R2": ["198.51.100.1", "198.51.100.4", "198.51.100.6"],
    "R3": ["198.51.100.1", "198.51.100.4"],
    "R4": ["198.51.100.2", "198.51.100.3", "198.51.100.7"],
}

EXPECTED_NEIGHBOR_COUNTS = {
    "R1": 2,
    "R2": 3,  # R1, R4, R6
    "R3": 2,
    "R4": 3,  # R2, R3, R7
}

# Expected loopbacks (should be reachable from any router)
LOOPBACKS = {
    "R1": "198.51.100.1",
    "R2": "198.51.100.2",
    "R3": "198.51.100.3",
    "R4": "198.51.100.4",
}


def get_connection(device_name):
    """Establish SSH connection to device."""
    return ConnectHandler(**DEVICES[device_name])


class TestOSPFNeighbors:
    """Test OSPF neighbor adjacencies."""

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_neighbor_count(self, device_name):
        """Each router should have the expected number of OSPF neighbors."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf neighbor")
        conn.disconnect()

        expected = EXPECTED_NEIGHBOR_COUNTS[device_name]
        full_count = output.count("FULL")
        assert full_count == expected, (
            f"{device_name} has {full_count} FULL neighbors, expected {expected}"
        )

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_neighbor_ids(self, device_name):
        """Verify correct neighbor router IDs."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf neighbor")
        conn.disconnect()

        expected = EXPECTED_NEIGHBORS[device_name]
        for neighbor_id in expected:
            assert neighbor_id in output, f"{device_name} missing neighbor {neighbor_id}"

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_no_ospf_neighbors_in_init(self, device_name):
        """No neighbors should be stuck in INIT state."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf neighbor")
        conn.disconnect()

        assert "INIT" not in output, f"{device_name} has neighbors in INIT state"


class TestOSPFConfiguration:
    """Test OSPF configuration correctness."""

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_process_running(self, device_name):
        """OSPF process 1 should be running."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip protocols")
        conn.disconnect()

        assert "ospf 1" in output.lower(), f"{device_name} OSPF process 1 not running"

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_router_id(self, device_name):
        """Router ID should match loopback address."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf | include with ID")
        conn.disconnect()

        expected_rid = LOOPBACKS[device_name]
        assert expected_rid in output, f"{device_name} Router ID not {expected_rid}"

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_area_0(self, device_name):
        """All interfaces should be in Area 0."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf interface brief")
        conn.disconnect()

        # Should have area 0 entries, no other areas
        assert "0" in output, f"{device_name} has no interfaces in Area 0"


class TestOSPFDatabase:
    """Test OSPF database consistency."""

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_database_has_all_routers(self, device_name):
        """OSPF database should have LSAs from all 4 routers."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf database router")
        conn.disconnect()

        for router_id in LOOPBACKS.values():
            assert router_id in output, f"{device_name} missing LSA from {router_id}"

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_database_router_lsa_count(self, device_name):
        """Should have exactly 4 Router LSAs (one per router)."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf database router")
        conn.disconnect()

        # Count unique router LSAs
        lsa_count = sum(1 for rid in LOOPBACKS.values() if rid in output)
        assert lsa_count == 4, f"{device_name} has {lsa_count} Router LSAs, expected 4"


class TestConnectivity:
    """Test end-to-end connectivity via OSPF routes."""

    @pytest.mark.parametrize("source,dest", [
        ("R1", "198.51.100.2"),
        ("R1", "198.51.100.3"),
        ("R1", "198.51.100.4"),
        ("R2", "198.51.100.1"),
        ("R2", "198.51.100.3"),
        ("R2", "198.51.100.4"),
        ("R3", "198.51.100.1"),
        ("R3", "198.51.100.2"),
        ("R3", "198.51.100.4"),
        ("R4", "198.51.100.1"),
        ("R4", "198.51.100.2"),
        ("R4", "198.51.100.3"),
    ])
    def test_ping_loopbacks(self, source, dest):
        """All loopbacks should be reachable from all routers."""
        conn = get_connection(source)
        output = conn.send_command(f"ping {dest} repeat 3")
        conn.disconnect()

        assert "Success rate is 100" in output, f"{source} cannot reach {dest}"

    @pytest.mark.parametrize("device_name", ["R1", "R2", "R3", "R4"])
    def test_ospf_routes_in_table(self, device_name):
        """Routing table should have OSPF routes to remote loopbacks."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip route ospf")
        conn.disconnect()

        # Should have routes to 3 other loopbacks
        own_loopback = LOOPBACKS[device_name]
        remote_loopbacks = [lb for lb in LOOPBACKS.values() if lb != own_loopback]

        for loopback in remote_loopbacks:
            assert loopback in output, f"{device_name} missing OSPF route to {loopback}"


class TestLANNetworks:
    """Test LAN networks are advertised in OSPF."""

    @pytest.mark.parametrize("device_name,lan_network", [
        ("R1", "10.1.0.0"),
        ("R2", "10.2.0.0"),
        ("R3", "10.3.0.0"),
        ("R4", "10.4.0.0"),
    ])
    def test_lan_in_ospf_database(self, device_name, lan_network):
        """LAN networks should be in OSPF database."""
        conn = get_connection(device_name)
        output = conn.send_command("show ip ospf database")
        conn.disconnect()

        # LAN networks should appear as stub networks in Router LSAs
        assert "10.1.0.0" in output or "10.2.0.0" in output, f"LAN networks not in OSPF database"

    @pytest.mark.parametrize("source,dest_lan", [
        ("R1", "10.2.0.1"),
        ("R1", "10.3.0.1"),
        ("R1", "10.4.0.1"),
        ("R4", "10.1.0.1"),
        ("R4", "10.2.0.1"),
        ("R4", "10.3.0.1"),
    ])
    def test_lan_reachability(self, source, dest_lan):
        """LAN gateways should be reachable across the network."""
        conn = get_connection(source)
        output = conn.send_command(f"ping {dest_lan} repeat 5")
        conn.disconnect()

        # Allow partial success (first packet may fail due to ARP resolution)
        assert "Success rate is 0" not in output, f"{source} cannot reach LAN {dest_lan}"


class TestConvergence:
    """Test OSPF convergence and path selection."""

    def test_ecmp_r1_to_r4(self):
        """R1 should have ECMP paths to R4 (via R2 and R3)."""
        conn = get_connection("R1")
        output = conn.send_command("show ip route 198.51.100.4")
        conn.disconnect()

        # Count number of next-hops in Routing Descriptor Blocks
        # Format: "10.0.x.x, from X.X.X.X, ... via GigabitEthernet"
        path_count = output.count("traffic share count")
        assert path_count == 2, f"R1 has {path_count} paths to 198.51.100.4, expected 2 (ECMP)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
