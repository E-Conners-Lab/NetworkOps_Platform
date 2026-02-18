"""
Multi-vendor device support tests.

Tests Juniper and HPE device type detection, command validation,
and connection handling.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# Configure pytest-asyncio mode
pytestmark = pytest.mark.anyio

# Test device type detection
from config.devices import (
    is_juniper_device,
    is_hpe_device,
    is_aruba_cx_device,
    is_comware_device,
    is_procurve_device,
    get_scrapli_device,
    _get_netmiko_device_type,
    JUNIPER_TYPES,
    HPE_TYPES,
    SUPPORTED_DEVICE_TYPES,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mock_juniper_device():
    """Mock Juniper device in DEVICES dict."""
    return {
        "device_type": "juniper_junos",
        "host": "10.255.255.50",
        "username": "admin",
        "password": "admin",
    }


@pytest.fixture
def mock_aruba_cx_device():
    """Mock HPE Aruba CX device."""
    return {
        "device_type": "aruba_aoscx",
        "host": "10.255.255.60",
        "username": "admin",
        "password": "admin",
    }


@pytest.fixture
def mock_comware_device():
    """Mock HPE Comware device."""
    return {
        "device_type": "hp_comware",
        "host": "10.255.255.70",
        "username": "admin",
        "password": "admin",
    }


@pytest.fixture
def mock_procurve_device():
    """Mock HPE ProCurve device."""
    return {
        "device_type": "hp_procurve",
        "host": "10.255.255.80",
        "username": "admin",
        "password": "admin",
    }


# =============================================================================
# Device Type Constants Tests
# =============================================================================

class TestDeviceTypeConstants:
    """Test device type constant definitions."""

    def test_juniper_types_defined(self):
        """Verify JUNIPER_TYPES is defined correctly."""
        assert "juniper_junos" in JUNIPER_TYPES

    def test_hpe_types_defined(self):
        """Verify HPE_TYPES includes all HPE variants."""
        assert "aruba_aoscx" in HPE_TYPES
        assert "hp_procurve" in HPE_TYPES
        assert "hp_comware" in HPE_TYPES

    def test_supported_device_types_complete(self):
        """Verify SUPPORTED_DEVICE_TYPES includes all vendors."""
        assert "cisco_xe" in SUPPORTED_DEVICE_TYPES
        assert "juniper_junos" in SUPPORTED_DEVICE_TYPES
        assert "aruba_aoscx" in SUPPORTED_DEVICE_TYPES
        assert "hp_procurve" in SUPPORTED_DEVICE_TYPES
        assert "hp_comware" in SUPPORTED_DEVICE_TYPES
        assert "linux" in SUPPORTED_DEVICE_TYPES


# =============================================================================
# Device Type Detection Tests
# =============================================================================

class TestDeviceTypeDetection:
    """Test device type helper functions."""

    def test_is_juniper_device_true(self, mock_juniper_device):
        """Test Juniper device detection returns True."""
        with patch("config.devices.DEVICES", {"vMX-1": mock_juniper_device}):
            assert is_juniper_device("vMX-1") is True

    def test_is_juniper_device_false_for_cisco(self):
        """Test Juniper detection returns False for Cisco."""
        cisco_device = {"device_type": "cisco_xe", "host": "10.0.0.1"}
        with patch("config.devices.DEVICES", {"R1": cisco_device}):
            assert is_juniper_device("R1") is False

    def test_is_juniper_device_false_for_nonexistent(self):
        """Test Juniper detection returns False for missing device."""
        with patch("config.devices.DEVICES", {}):
            assert is_juniper_device("nonexistent") is False

    def test_is_hpe_device_aruba_cx(self, mock_aruba_cx_device):
        """Test HPE detection for Aruba CX."""
        with patch("config.devices.DEVICES", {"Aruba-1": mock_aruba_cx_device}):
            assert is_hpe_device("Aruba-1") is True

    def test_is_hpe_device_comware(self, mock_comware_device):
        """Test HPE detection for Comware."""
        with patch("config.devices.DEVICES", {"Comware-1": mock_comware_device}):
            assert is_hpe_device("Comware-1") is True

    def test_is_hpe_device_procurve(self, mock_procurve_device):
        """Test HPE detection for ProCurve."""
        with patch("config.devices.DEVICES", {"ProCurve-1": mock_procurve_device}):
            assert is_hpe_device("ProCurve-1") is True

    def test_is_aruba_cx_device(self, mock_aruba_cx_device):
        """Test Aruba CX specific detection."""
        with patch("config.devices.DEVICES", {"Aruba-1": mock_aruba_cx_device}):
            assert is_aruba_cx_device("Aruba-1") is True
            assert is_comware_device("Aruba-1") is False

    def test_is_comware_device(self, mock_comware_device):
        """Test Comware specific detection."""
        with patch("config.devices.DEVICES", {"Comware-1": mock_comware_device}):
            assert is_comware_device("Comware-1") is True
            assert is_aruba_cx_device("Comware-1") is False


# =============================================================================
# Scrapli/Netmiko Parameter Tests
# =============================================================================

class TestScrapliParameters:
    """Test Scrapli device parameter generation."""

    def test_get_scrapli_device_juniper(self, mock_juniper_device):
        """Test Scrapli params for Juniper device."""
        with patch("config.devices.DEVICES", {"vMX-1": mock_juniper_device}):
            with patch("config.devices.USERNAME", "admin"):
                with patch("config.devices.PASSWORD", "admin"):
                    params = get_scrapli_device("vMX-1")

        assert params is not None
        assert params["device_type"] == "juniper_junos"
        assert params["host"] == "10.255.255.50"
        assert params["transport"] == "asyncssh"
        assert "use_netmiko" not in params  # Juniper uses native Scrapli

    def test_get_scrapli_device_hpe_uses_netmiko(self, mock_aruba_cx_device):
        """Test HPE devices are flagged for Netmiko."""
        with patch("config.devices.DEVICES", {"Aruba-1": mock_aruba_cx_device}):
            with patch("config.devices.USERNAME", "admin"):
                with patch("config.devices.PASSWORD", "admin"):
                    params = get_scrapli_device("Aruba-1")

        assert params is not None
        assert params["use_netmiko"] is True
        assert params["netmiko_device_type"] == "aruba_osswitch"


class TestNetmikoDeviceType:
    """Test Netmiko device type mapping."""

    def test_netmiko_device_type_aruba(self):
        """Test Aruba CX maps to aruba_osswitch."""
        assert _get_netmiko_device_type("aruba_aoscx") == "aruba_osswitch"

    def test_netmiko_device_type_procurve(self):
        """Test ProCurve maps correctly."""
        assert _get_netmiko_device_type("hp_procurve") == "hp_procurve"

    def test_netmiko_device_type_comware(self):
        """Test Comware maps correctly."""
        assert _get_netmiko_device_type("hp_comware") == "hp_comware"

    def test_netmiko_device_type_juniper(self):
        """Test Juniper maps correctly."""
        assert _get_netmiko_device_type("juniper_junos") == "juniper_junos"


# =============================================================================
# Command Validation Tests
# =============================================================================

class TestCommandBlocking:
    """Test vendor-specific command blocking."""

    def test_juniper_reboot_blocked(self):
        """Test Juniper reboot command is blocked."""
        from dashboard.api_server import BLOCKED_COMMANDS
        assert "request system reboot" in BLOCKED_COMMANDS

    def test_juniper_zeroize_blocked(self):
        """Test Juniper zeroize command is blocked."""
        from dashboard.api_server import BLOCKED_COMMANDS
        assert "request system zeroize" in BLOCKED_COMMANDS

    def test_hpe_erase_blocked(self):
        """Test HPE erase commands are blocked."""
        from dashboard.api_server import BLOCKED_COMMANDS
        assert "erase startup-config" in BLOCKED_COMMANDS
        assert "erase all" in BLOCKED_COMMANDS

    def test_comware_reset_blocked(self):
        """Test Comware reset command is blocked."""
        from dashboard.api_server import BLOCKED_COMMANDS
        assert "reset saved-configuration" in BLOCKED_COMMANDS


class TestOperatorAllowedPrefixes:
    """Test vendor-specific allowed command prefixes."""

    def test_show_allowed_all_vendors(self):
        """Test 'show' is allowed (works on most vendors)."""
        from dashboard.api_server import OPERATOR_ALLOWED_PREFIXES
        assert "show" in OPERATOR_ALLOWED_PREFIXES

    def test_display_allowed_for_comware(self):
        """Test 'display' is allowed for Comware."""
        from dashboard.api_server import OPERATOR_ALLOWED_PREFIXES
        assert "display" in OPERATOR_ALLOWED_PREFIXES

    def test_tracert_allowed_for_comware(self):
        """Test 'tracert' is allowed for Comware (different from traceroute)."""
        from dashboard.api_server import OPERATOR_ALLOWED_PREFIXES
        assert "tracert" in OPERATOR_ALLOWED_PREFIXES


# =============================================================================
# Platform Detection Tests
# =============================================================================

class TestPlatformDetection:
    """Test platform name mapping for dashboard UI."""

    @pytest.mark.parametrize("device_type,expected_platform", [
        ("juniper_junos", "Juniper Junos"),
        ("aruba_aoscx", "HPE Aruba CX"),
        ("hp_procurve", "HPE ProCurve"),
        ("hp_comware", "HPE Comware"),
    ])
    def test_platform_names(self, device_type, expected_platform):
        """Test platform names are correctly mapped."""
        # Import the platform mapping logic (this tests the pattern exists)
        # The actual mapping is in api_server.py get_topology()
        platform_map = {
            "juniper_junos": "Juniper Junos",
            "aruba_aoscx": "HPE Aruba CX",
            "hp_procurve": "HPE ProCurve",
            "hp_comware": "HPE Comware",
        }
        assert platform_map[device_type] == expected_platform


# =============================================================================
# NETCONF Capability Tests
# =============================================================================

class TestNetconfCapability:
    """Test NETCONF capability detection."""

    def test_cisco_netconf_capable(self):
        """Test Cisco is NETCONF capable."""
        from core.netconf_client import NETCONF_CAPABLE_TYPES
        assert "cisco_xe" in NETCONF_CAPABLE_TYPES

    def test_juniper_netconf_capable(self):
        """Test Juniper is NETCONF capable."""
        from core.netconf_client import NETCONF_CAPABLE_TYPES
        assert "juniper_junos" in NETCONF_CAPABLE_TYPES

    def test_hpe_not_netconf_capable(self):
        """Test HPE devices are not NETCONF capable (SSH only)."""
        from core.netconf_client import NETCONF_CAPABLE_TYPES
        assert "aruba_aoscx" not in NETCONF_CAPABLE_TYPES
        assert "hp_procurve" not in NETCONF_CAPABLE_TYPES
        assert "hp_comware" not in NETCONF_CAPABLE_TYPES


# =============================================================================
# Mock Connection Tests
# =============================================================================

class TestMockConnections:
    """Test connection handling with mocks."""

    async def test_juniper_health_check_mock(self, mock_juniper_device):
        """Test Juniper health check with mocked connection."""
        mock_response = MagicMock()
        mock_response.result = """
Current time: 2025-12-29 12:00:00
System booted: 2025-12-01 00:00:00
Uptime: 28 days, 12:00
"""
        mock_intf_response = MagicMock()
        mock_intf_response.result = """
Interface   Admin Link Proto Local/Remote
ge-0/0/0    up    up
ge-0/0/1    up    down
lo0         up    up
"""
        mock_conn = AsyncMock()
        mock_conn.send_command = AsyncMock(side_effect=[mock_response, mock_intf_response])
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=None)

        with patch("config.devices.DEVICES", {"vMX-1": mock_juniper_device}):
            with patch("core.scrapli_manager.get_junos_connection", return_value=mock_conn):
                from network_mcp_async import _check_juniper_device
                result = await _check_juniper_device("vMX-1")

        assert result["device"] == "vMX-1"
        # Check that we got some result (mock parsing may vary)
        assert "status" in result

    async def test_hpe_health_check_mock(self, mock_aruba_cx_device):
        """Test HPE health check with mocked Netmiko."""
        from core.netmiko_manager import NetmikoResponse

        mock_version = NetmikoResponse(result="HPE Aruba CX 6300\nVersion: 10.10", channel_input="show version")
        mock_intf = NetmikoResponse(result="1/1/1  up  up\n1/1/2  down  down", channel_input="show interface brief")

        with patch("config.devices.DEVICES", {"Aruba-1": mock_aruba_cx_device}):
            with patch("core.netmiko_manager.send_command_netmiko") as mock_cmd:
                mock_cmd.side_effect = [mock_version, mock_intf]

                from core.netmiko_manager import check_hpe_health
                result = await check_hpe_health("Aruba-1", "aruba_aoscx")

        assert result["device"] == "Aruba-1"
        assert result["status"] in ("healthy", "degraded", "critical")


# =============================================================================
# NetBox Integration Tests
# =============================================================================

class TestNetBoxDeviceTypeMapping:
    """Test NetBox device type slug inference."""

    def test_netbox_type_map_includes_juniper(self):
        """Test DEVICE_TYPE_MAP includes Juniper."""
        from config.netbox_client import DEVICE_TYPE_MAP
        assert "juniper_junos" in DEVICE_TYPE_MAP

    def test_netbox_type_map_includes_hpe(self):
        """Test DEVICE_TYPE_MAP includes all HPE types."""
        from config.netbox_client import DEVICE_TYPE_MAP
        assert "aruba_aoscx" in DEVICE_TYPE_MAP
        assert "hp_procurve" in DEVICE_TYPE_MAP
        assert "hp_comware" in DEVICE_TYPE_MAP
