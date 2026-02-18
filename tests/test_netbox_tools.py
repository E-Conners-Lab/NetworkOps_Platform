"""Tests for NetBox MCP tools.

Validates input handling, error shapes, response contracts, and safety
guardrails using mocked NetBox client.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

# Patch target for the NetBox client (lazy-imported inside tool functions)
_CLIENT_PATCH = "config.netbox_client.get_client"
_AVAIL_PATCH = "config.netbox_client.is_netbox_available"
_TOKEN_PATCH = "config.netbox_client.NETBOX_API_TOKEN"


# =============================================================================
# Helpers
# =============================================================================

def _parse(result: str) -> dict:
    """Parse JSON tool result."""
    return json.loads(result)


# =============================================================================
# Unavailable Handling
# =============================================================================

class TestNetBoxUnavailable:
    """Tools should return a consistent error when NetBox is down."""

    def _mock_client(self):
        """Create a mock client with JSON-serializable circuit breaker."""
        client = Mock()
        client.get_circuit_status.return_value = {
            "state": "open", "failure_count": 3,
            "is_allowing_requests": False, "service": "netbox",
        }
        return client

    @patch(_AVAIL_PATCH, return_value=False)
    @patch(_CLIENT_PATCH)
    def test_get_devices_unavailable(self, mock_get_client, mock_avail):
        mock_get_client.return_value = self._mock_client()
        from mcp_tools.netbox import netbox_get_devices
        result = _parse(netbox_get_devices())
        assert "error" in result
        assert "not available" in result["error"]

    @patch(_AVAIL_PATCH, return_value=False)
    @patch(_CLIENT_PATCH)
    def test_get_interfaces_unavailable(self, mock_get_client, mock_avail):
        mock_get_client.return_value = self._mock_client()
        from mcp_tools.netbox import netbox_get_interfaces
        result = _parse(netbox_get_interfaces("R1"))
        assert "error" in result

    @patch(_AVAIL_PATCH, return_value=False)
    @patch(_CLIENT_PATCH)
    def test_suggest_ip_unavailable(self, mock_get_client, mock_avail):
        mock_get_client.return_value = self._mock_client()
        from mcp_tools.netbox import netbox_suggest_ip
        result = _parse(netbox_suggest_ip("10.0.0.0/24"))
        assert "error" in result

    @patch(_AVAIL_PATCH, return_value=False)
    @patch(_CLIENT_PATCH)
    def test_allocate_ip_unavailable(self, mock_get_client, mock_avail):
        mock_get_client.return_value = self._mock_client()
        from mcp_tools.netbox import netbox_allocate_ip
        result = _parse(netbox_allocate_ip("10.0.0.0/24"))
        assert "error" in result


# =============================================================================
# Input Validation
# =============================================================================

class TestInputValidation:
    """Tools should validate inputs and return clear errors."""

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_get_interfaces_device_not_found(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_get_interfaces

        mock_client = Mock()
        mock_client.api.dcim.devices.get.return_value = None
        mock_get_client.return_value = mock_client

        result = _parse(netbox_get_interfaces("NONEXISTENT"))

        assert "error" in result
        assert "NONEXISTENT" in result["error"]

    @patch(_AVAIL_PATCH, return_value=True)
    def test_suggest_ip_empty_prefix(self, mock_avail):
        from mcp_tools.netbox import netbox_suggest_ip
        result = _parse(netbox_suggest_ip(""))
        assert "error" in result
        assert "required" in result["error"]

    @patch(_AVAIL_PATCH, return_value=True)
    def test_allocate_ip_empty_prefix(self, mock_avail):
        from mcp_tools.netbox import netbox_allocate_ip
        result = _parse(netbox_allocate_ip(""))
        assert "error" in result
        assert "required" in result["error"]

    @patch(_AVAIL_PATCH, return_value=True)
    def test_release_ip_empty_address(self, mock_avail):
        from mcp_tools.netbox import netbox_release_ip
        result = _parse(netbox_release_ip(""))
        assert "error" in result
        assert "required" in result["error"]

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_get_devices_bad_role(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_get_devices

        mock_client = Mock()
        mock_client.tenant = ""
        mock_client.api.dcim.device_roles.get.return_value = None
        mock_client.api.dcim.device_roles.filter.return_value = []
        mock_get_client.return_value = mock_client

        result = _parse(netbox_get_devices(role="nonexistent_role"))

        assert "error" in result
        assert "Role not found" in result["error"]


# =============================================================================
# Response Contract Key Sets
# =============================================================================

class TestResponseContracts:
    """Verify exact key sets on tool responses to catch breaking changes."""

    @patch(_TOKEN_PATCH, "test-token")
    @patch(_CLIENT_PATCH)
    def test_status_keys(self, mock_get_client):
        from mcp_tools.netbox import netbox_status

        mock_client = Mock()
        mock_client.get_circuit_status.return_value = {
            "state": "closed", "failure_count": 0,
            "is_allowing_requests": True, "service": "netbox",
        }
        mock_client._cache = {"devices": {}}
        mock_client._cache_timestamps = {}
        mock_client.api.status.return_value = {"netbox-version": "4.1.0"}
        mock_client.get_devices.return_value = {"R1": {}, "R2": {}}
        mock_get_client.return_value = mock_client

        result = _parse(netbox_status())

        expected_keys = {
            "available", "url", "version", "circuit_breaker",
            "cache", "data_source", "device_count", "last_success_ts",
        }
        assert set(result.keys()) == expected_keys

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_get_devices_keys(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_get_devices

        mock_device = Mock()
        mock_device.name = "R1"
        mock_device.role = Mock(slug="router")
        mock_device.site = Mock(slug="eve-ng-lab")
        mock_device.location = Mock(slug="core-routers")
        mock_device.device_type = Mock(model="C8000V")
        mock_device.primary_ip4 = Mock(address="10.255.255.11/24")
        mock_device.status = Mock(value="active")

        mock_client = Mock()
        mock_client.tenant = ""
        mock_client.api.dcim.devices.all.return_value = [mock_device]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_get_devices())

        assert set(result.keys()) == {"source", "count", "devices"}
        assert result["count"] == 1

        device = result["devices"][0]
        expected_device_keys = {
            "name", "role", "site", "location",
            "device_type", "primary_ip", "status",
        }
        assert set(device.keys()) == expected_device_keys

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_get_interfaces_keys(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_get_interfaces

        mock_device = Mock()
        mock_device.id = 1

        mock_ip = Mock()
        mock_ip.address = "10.1.0.1/30"
        mock_ip.status = Mock(value="active")
        mock_ip.vrf = None

        mock_intf = Mock()
        mock_intf.name = "GigabitEthernet1"
        mock_intf.type = Mock(value="1000base-t")
        mock_intf.enabled = True
        mock_intf.description = "Uplink"
        mock_intf.id = 10

        mock_client = Mock()
        mock_client.api.dcim.devices.get.return_value = mock_device
        mock_client.api.dcim.interfaces.filter.return_value = [mock_intf]
        mock_client.api.ipam.ip_addresses.filter.return_value = [mock_ip]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_get_interfaces("R1"))

        assert set(result.keys()) == {"device", "interface_count", "interfaces"}
        intf = result["interfaces"][0]
        assert set(intf.keys()) == {"name", "type", "enabled", "description", "ip_addresses"}
        # IP is an object, not a string
        ip = intf["ip_addresses"][0]
        assert set(ip.keys()) == {"address", "status", "vrf"}

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_hierarchy_keys(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_get_hierarchy

        mock_region = Mock()
        mock_region.slug = "us-west"
        mock_region.name = "US West"

        mock_site = Mock()
        mock_site.slug = "eve-ng-lab"
        mock_site.name = "EVE-NG Lab"
        mock_site.region = Mock(slug="us-west")

        mock_loc = Mock()
        mock_loc.slug = "core-routers"
        mock_loc.name = "Core Routers"
        mock_loc.site = Mock(slug="eve-ng-lab")

        mock_device = Mock()
        mock_device.name = "R1"
        mock_device.location = Mock(slug="core-routers")

        mock_client = Mock()
        mock_client.api.dcim.regions.all.return_value = [mock_region]
        mock_client.api.dcim.sites.all.return_value = [mock_site]
        mock_client.api.dcim.locations.all.return_value = [mock_loc]
        mock_client.api.dcim.devices.all.return_value = [mock_device]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_get_hierarchy())

        assert set(result.keys()) == {"source", "regions"}
        region = result["regions"][0]
        assert set(region.keys()) == {"name", "slug", "sites"}
        site = region["sites"][0]
        assert set(site.keys()) == {"name", "slug", "locations"}
        loc = site["locations"][0]
        assert set(loc.keys()) == {"name", "slug", "devices"}
        assert loc["devices"] == ["R1"]


# =============================================================================
# Release IP Guardrail
# =============================================================================

class TestReleaseGuardrail:
    """netbox_release_ip should refuse to release assigned IPs without force."""

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_refuses_assigned_ip_without_force(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_release_ip

        mock_ip = Mock()
        mock_ip.status = Mock(value="active")
        mock_ip.assigned_object = Mock()
        mock_ip.assigned_object.name = "GigabitEthernet4"
        mock_device = Mock()
        mock_device.name = "R1"
        mock_ip.assigned_object.device = mock_device

        mock_client = Mock()
        mock_client.api.ipam.ip_addresses.filter.return_value = [mock_ip]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_release_ip("10.255.255.11"))

        assert "error" in result
        assert "assigned" in result["error"].lower()
        assert "force" in result["error"].lower()
        assert "assigned_to" in result
        mock_ip.delete.assert_not_called()

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_releases_assigned_ip_with_force(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_release_ip

        mock_ip = Mock()
        mock_ip.status = Mock(value="active")
        mock_ip.assigned_object = Mock()
        mock_ip.assigned_object.name = "GigabitEthernet4"
        mock_device = Mock()
        mock_device.name = "R1"
        mock_ip.assigned_object.device = mock_device

        mock_client = Mock()
        mock_client.api.ipam.ip_addresses.filter.return_value = [mock_ip]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_release_ip("10.255.255.11", force=True))

        assert result["action"] == "released"
        assert result["was_assigned"] is True
        mock_ip.delete.assert_called_once()

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_releases_unassigned_ip(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_release_ip

        mock_ip = Mock()
        mock_ip.status = Mock(value="active")
        mock_ip.assigned_object = None

        mock_client = Mock()
        mock_client.api.ipam.ip_addresses.filter.return_value = [mock_ip]
        mock_get_client.return_value = mock_client

        result = _parse(netbox_release_ip("10.255.255.48"))

        assert result["action"] == "released"
        assert result["was_assigned"] is False
        mock_ip.delete.assert_called_once()

    @patch(_AVAIL_PATCH, return_value=True)
    @patch(_CLIENT_PATCH)
    def test_ip_not_found(self, mock_get_client, mock_avail):
        from mcp_tools.netbox import netbox_release_ip

        mock_client = Mock()
        mock_client.api.ipam.ip_addresses.filter.return_value = []
        mock_get_client.return_value = mock_client

        result = _parse(netbox_release_ip("10.255.255.99"))

        assert "error" in result
        assert "not found" in result["error"].lower()


# =============================================================================
# Tool Registry
# =============================================================================

class TestToolRegistry:
    """Verify tools are registered correctly."""

    def test_tool_count(self):
        from mcp_tools.netbox import TOOLS
        assert len(TOOLS) == 14

    def test_all_tools_have_required_keys(self):
        from mcp_tools.netbox import TOOLS
        for tool in TOOLS:
            assert "fn" in tool
            assert "name" in tool
            assert "category" in tool
            assert tool["category"] == "netbox"
            assert callable(tool["fn"])

    def test_tool_names_are_unique(self):
        from mcp_tools.netbox import TOOLS
        names = [t["name"] for t in TOOLS]
        assert len(names) == len(set(names))

    def test_tools_in_all_tools_registry(self):
        from mcp_tools import ALL_TOOLS
        netbox_tools = [t for t in ALL_TOOLS if t["category"] == "netbox"]
        assert len(netbox_tools) == 14
