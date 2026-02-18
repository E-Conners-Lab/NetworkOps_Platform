"""Tests for NetBox IP allocation functionality.

Phase 4.5: Auto-allocate IPs from 10.255.255.0/24 for device provisioning.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestGetNextAvailableIP:
    """Tests for get_next_available_ip method."""

    @patch("config.netbox_client.pynetbox")
    def test_returns_first_available_ip(self, mock_pynetbox):
        """Should return first unused IP after .1 gateway."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")

        # Mock prefix exists
        mock_prefix = Mock()
        client._api = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix

        # Mock used IPs: .11, .12, .13 are used
        used_ips = [
            Mock(address="10.255.255.11/24"),
            Mock(address="10.255.255.12/24"),
            Mock(address="10.255.255.13/24"),
        ]
        client._api.ipam.ip_addresses.filter.return_value = used_ips

        result = client.get_next_available_ip("10.255.255.0/24")

        # Should return .2 (first after .1 gateway)
        assert result == "10.255.255.2/24"

    @patch("config.netbox_client.pynetbox")
    def test_skips_gateway_address(self, mock_pynetbox):
        """Should skip .1 gateway address."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")

        mock_prefix = Mock()
        client._api = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix

        # .1 is "used" by gateway, .2 is used
        used_ips = [
            Mock(address="10.255.255.2/24"),
        ]
        client._api.ipam.ip_addresses.filter.return_value = used_ips

        result = client.get_next_available_ip("10.255.255.0/24")

        # Should skip .1 (gateway) and .2 (used), return .3
        assert result == "10.255.255.3/24"

    @patch("config.netbox_client.pynetbox")
    def test_raises_error_on_invalid_prefix(self, mock_pynetbox):
        """Should raise ValueError for invalid prefix format."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        with pytest.raises(ValueError, match="Invalid prefix format"):
            client.get_next_available_ip("not-a-valid-prefix")

    @patch("config.netbox_client.pynetbox")
    def test_raises_error_when_prefix_not_found(self, mock_pynetbox):
        """Should raise ValueError when prefix doesn't exist in NetBox."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()
        client._api.ipam.prefixes.get.return_value = None

        with pytest.raises(ValueError, match="not found in NetBox IPAM"):
            client.get_next_available_ip("10.255.255.0/24")

    @patch("config.netbox_client.pynetbox")
    def test_raises_error_when_prefix_exhausted(self, mock_pynetbox):
        """Should raise ValueError when no IPs available."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")

        mock_prefix = Mock()
        client._api = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix

        # All IPs except .1 are used (for a /30 to test exhaustion)
        used_ips = [
            Mock(address="10.255.255.2/30"),
        ]
        client._api.ipam.ip_addresses.filter.return_value = used_ips

        with pytest.raises(ValueError, match="exhausted"):
            # Using /30 which only has .1, .2 as hosts (.1 skipped, .2 used)
            client.get_next_available_ip("10.255.255.0/30")

    @patch("config.netbox_client.pynetbox")
    def test_finds_gap_in_used_ips(self, mock_pynetbox):
        """Should find available IP in gap between used IPs."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")

        mock_prefix = Mock()
        client._api = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix

        # .2, .3, .4 used but .5 is skipped (gap), .6 used
        used_ips = [
            Mock(address="10.255.255.2/24"),
            Mock(address="10.255.255.3/24"),
            Mock(address="10.255.255.4/24"),
            Mock(address="10.255.255.6/24"),
        ]
        client._api.ipam.ip_addresses.filter.return_value = used_ips

        result = client.get_next_available_ip("10.255.255.0/24")

        # Should find .5 (gap)
        assert result == "10.255.255.5/24"


class TestAllocateIP:
    """Tests for allocate_ip method."""

    @patch("config.netbox_client.pynetbox")
    def test_allocates_ip_without_device(self, mock_pynetbox):
        """Should allocate IP without assigning to device."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock get_next_available_ip
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        # Mock IP creation
        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        result = client.allocate_ip("10.255.255.0/24")

        assert result["address"] == "10.255.255.2/24"
        assert result["id"] == 123
        assert result["assigned_to"] is None

        # Verify IP was created
        client._api.ipam.ip_addresses.create.assert_called_once()

    @patch("config.netbox_client.pynetbox")
    def test_allocates_ip_to_device(self, mock_pynetbox):
        """Should allocate IP and assign to device interface."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock get_next_available_ip
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        # Mock device lookup
        mock_device = Mock()
        mock_device.id = 1
        client._api.dcim.devices.get.return_value = mock_device

        # Mock interface lookup
        mock_intf = Mock()
        mock_intf.id = 10
        client._api.dcim.interfaces.get.return_value = mock_intf

        # Mock IP creation
        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        result = client.allocate_ip(
            prefix="10.255.255.0/24",
            device_name="R8",
            interface_name="GigabitEthernet4",
        )

        assert result["address"] == "10.255.255.2/24"
        assert result["id"] == 123
        assert result["assigned_to"] == "R8:GigabitEthernet4"

        # Verify IP was assigned to interface
        call_kwargs = client._api.ipam.ip_addresses.create.call_args[1]
        assert call_kwargs["assigned_object_type"] == "dcim.interface"
        assert call_kwargs["assigned_object_id"] == 10

    @patch("config.netbox_client.pynetbox")
    def test_creates_interface_if_not_exists(self, mock_pynetbox):
        """Should create interface if it doesn't exist on device."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock get_next_available_ip
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        # Mock device lookup
        mock_device = Mock()
        mock_device.id = 1
        client._api.dcim.devices.get.return_value = mock_device

        # Interface doesn't exist
        client._api.dcim.interfaces.get.return_value = None

        # Mock interface creation
        created_intf = Mock()
        created_intf.id = 99
        client._api.dcim.interfaces.create.return_value = created_intf

        # Mock IP creation
        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        result = client.allocate_ip(
            prefix="10.255.255.0/24",
            device_name="R8",
        )

        # Verify interface was created
        client._api.dcim.interfaces.create.assert_called_once()
        create_call = client._api.dcim.interfaces.create.call_args[1]
        assert create_call["device"] == 1
        assert create_call["name"] == "GigabitEthernet4"

    @patch("config.netbox_client.pynetbox")
    def test_raises_error_when_device_not_found(self, mock_pynetbox):
        """Should raise ValueError when device doesn't exist."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock get_next_available_ip
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        # Device doesn't exist
        client._api.dcim.devices.get.return_value = None

        with pytest.raises(ValueError, match="Device not found"):
            client.allocate_ip(
                prefix="10.255.255.0/24",
                device_name="NonExistentDevice",
            )

    @patch("config.netbox_client.pynetbox")
    def test_sets_primary_ip_on_device(self, mock_pynetbox):
        """Should set allocated IP as device's primary IP."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock get_next_available_ip
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        # Mock device lookup
        mock_device = Mock()
        mock_device.id = 1
        client._api.dcim.devices.get.return_value = mock_device

        # Mock interface lookup
        mock_intf = Mock()
        mock_intf.id = 10
        client._api.dcim.interfaces.get.return_value = mock_intf

        # Mock IP creation
        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        client.allocate_ip(
            prefix="10.255.255.0/24",
            device_name="R8",
        )

        # Verify primary_ip4 was set and saved
        assert mock_device.primary_ip4 == 123
        mock_device.save.assert_called_once()


class TestReleaseIP:
    """Tests for release_ip method."""

    @patch("config.netbox_client.pynetbox")
    def test_releases_existing_ip(self, mock_pynetbox):
        """Should delete IP from NetBox."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock IP found
        mock_ip = Mock()
        client._api.ipam.ip_addresses.filter.return_value = [mock_ip]

        result = client.release_ip("10.255.255.48/24")

        assert result is True
        mock_ip.delete.assert_called_once()

    @patch("config.netbox_client.pynetbox")
    def test_handles_ip_without_cidr(self, mock_pynetbox):
        """Should handle IP address without CIDR suffix."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Mock IP found
        mock_ip = Mock()
        client._api.ipam.ip_addresses.filter.return_value = [mock_ip]

        result = client.release_ip("10.255.255.48")  # No /24

        assert result is True
        mock_ip.delete.assert_called_once()

    @patch("config.netbox_client.pynetbox")
    def test_returns_false_when_ip_not_found(self, mock_pynetbox):
        """Should return False when IP doesn't exist."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # IP not found
        client._api.ipam.ip_addresses.filter.return_value = []

        result = client.release_ip("10.255.255.99/24")

        assert result is False

    @patch("config.netbox_client.pynetbox")
    def test_clears_cache_after_release(self, mock_pynetbox):
        """Should clear cache after releasing IP."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()
        client._cache = {"some": "data"}
        client._cache_timestamps = {"some": 123}

        # Mock IP found
        mock_ip = Mock()
        client._api.ipam.ip_addresses.filter.return_value = [mock_ip]

        client.release_ip("10.255.255.48/24")

        # Cache should be cleared
        assert client._cache == {}
        assert client._cache_timestamps == {}


class TestIPAllocationIntegration:
    """Integration-style tests for the allocation workflow."""

    @patch("config.netbox_client.pynetbox")
    def test_allocation_and_release_workflow(self, mock_pynetbox):
        """Test full allocate -> release workflow."""
        from config.netbox_client import NetBoxClient

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        # Setup for allocation
        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        # Allocate
        result = client.allocate_ip("10.255.255.0/24")
        allocated_ip = result["address"]

        # Setup for release
        mock_ip = Mock()
        client._api.ipam.ip_addresses.filter.return_value = [mock_ip]

        # Release
        released = client.release_ip(allocated_ip)

        assert released is True
        mock_ip.delete.assert_called_once()

    @patch("config.netbox_client.pynetbox")
    def test_correlation_id_passed_through(self, mock_pynetbox):
        """Verify correlation ID is used in logging."""
        from config.netbox_client import NetBoxClient
        import logging

        client = NetBoxClient(token="test-token")
        client._api = Mock()

        mock_prefix = Mock()
        client._api.ipam.prefixes.get.return_value = mock_prefix
        client._api.ipam.ip_addresses.filter.return_value = []

        created_ip = Mock()
        created_ip.id = 123
        client._api.ipam.ip_addresses.create.return_value = created_ip

        with patch.object(logging, "getLogger") as mock_logger:
            mock_log = Mock()
            mock_logger.return_value = mock_log

            client.allocate_ip(
                prefix="10.255.255.0/24",
                correlation_id="test-corr-123",
            )

            # Verify correlation ID appears in log messages
            # (Can't easily check message content with mock, but at least verify logging called)
            assert mock_log.info.called
