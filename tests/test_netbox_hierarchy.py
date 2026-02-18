#!/usr/bin/env python3
"""
NetBox Hierarchy Integration Tests

Tests for the NetBox integration with the hierarchy provider.
Tests both NetBox mode and static fallback mode.

Usage:
    pytest tests/test_netbox_hierarchy.py -v
    pytest tests/test_netbox_hierarchy.py -v -k "static"  # Static tests only
    pytest tests/test_netbox_hierarchy.py -v -k "netbox"  # NetBox tests only
"""

import os
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.hierarchy import (
    HierarchyProvider,
    get_hierarchy_provider,
    REGIONS,
    SITES,
    RACKS,
    DEVICE_LOCATIONS,
)


# =============================================================================
# Provider Tests - Static Mode
# =============================================================================

class TestHierarchyProviderStaticMode:
    """Tests for HierarchyProvider when NetBox is not available"""

    @pytest.fixture
    def provider(self):
        """Create a provider that doesn't use NetBox"""
        with patch.dict(os.environ, {"USE_NETBOX": "false"}):
            from config import hierarchy
            hierarchy._provider = None  # Reset singleton
            provider = HierarchyProvider()
            provider._use_netbox = False
            provider._netbox_available = False
            yield provider
            hierarchy._provider = None  # Cleanup

    def test_static_get_data_source(self, provider):
        """Static mode returns 'static' as data source"""
        assert provider.get_data_source() == "static"

    def test_static_get_regions_returns_static_data(self, provider):
        """get_regions returns static REGIONS when NetBox unavailable"""
        regions = provider.get_regions()
        assert regions == REGIONS
        assert len(regions) >= 1

    def test_static_get_sites_returns_static_data(self, provider):
        """get_sites returns static SITES when NetBox unavailable"""
        sites = provider.get_sites()
        assert sites == SITES
        assert len(sites) >= 1

    def test_static_get_racks_returns_static_data(self, provider):
        """get_racks returns static RACKS when NetBox unavailable"""
        racks = provider.get_racks()
        assert racks == RACKS
        assert len(racks) >= 1

    def test_static_get_device_locations_returns_static_data(self, provider):
        """get_device_locations returns static DEVICE_LOCATIONS when NetBox unavailable"""
        locations = provider.get_device_locations()
        assert locations == DEVICE_LOCATIONS
        assert len(locations) >= 1

    def test_static_get_hierarchy_tree_structure(self, provider):
        """get_hierarchy_tree returns valid structure in static mode"""
        tree = provider.get_hierarchy_tree()
        assert "regions" in tree
        assert len(tree["regions"]) >= 1

        for region in tree["regions"]:
            assert "id" in region
            assert "name" in region
            assert "sites" in region

    def test_static_get_device_hierarchy_found(self, provider):
        """get_device_hierarchy returns correct path for known device"""
        hierarchy = provider.get_device_hierarchy("R1")
        assert hierarchy is not None
        assert hierarchy["region"] == "us-west"
        assert hierarchy["site"] == "eve-ng-lab"
        assert hierarchy["rack"] == "core-rack"

    def test_static_get_device_hierarchy_not_found(self, provider):
        """get_device_hierarchy returns None for unknown device"""
        hierarchy = provider.get_device_hierarchy("NonexistentDevice")
        assert hierarchy is None

    def test_static_get_devices_in_rack(self, provider):
        """get_devices_in_rack returns correct devices"""
        devices = provider.get_devices_in_rack("core-rack")
        assert "R1" in devices
        assert "R2" in devices
        assert "R3" in devices
        assert "R4" in devices

    def test_static_get_devices_in_site(self, provider):
        """get_devices_in_site returns devices from all racks"""
        devices = provider.get_devices_in_site("eve-ng-lab")
        assert "R1" in devices  # core-rack
        assert "Switch-R1" in devices  # switch-rack
        assert "Alpine-1" in devices  # host-rack

    def test_static_get_devices_in_region(self, provider):
        """get_devices_in_region returns devices from all sites"""
        devices = provider.get_devices_in_region("us-west")
        assert "R1" in devices
        assert "Switch-R1" in devices


# =============================================================================
# Provider Tests - NetBox Mode (Mocked)
# =============================================================================

class TestHierarchyProviderNetBoxMode:
    """Tests for HierarchyProvider when NetBox is available (mocked)"""

    @pytest.fixture
    def mock_netbox_client(self):
        """Create a mock NetBox client"""
        client = Mock()

        # Mock data
        client.get_regions.return_value = [
            {"id": "us-west", "name": "US West"},
            {"id": "containerlab", "name": "Containerlab"},
        ]

        client.get_sites.return_value = [
            {"id": "eve-ng-lab", "name": "EVE-NG Lab", "region": "us-west"},
            {"id": "containerlab-vm", "name": "Containerlab VM", "region": "containerlab"},
        ]

        client.get_locations.return_value = [
            {"id": "core-rack", "name": "Core Routers", "site": "eve-ng-lab"},
            {"id": "switch-rack", "name": "Switches", "site": "eve-ng-lab"},
            {"id": "host-rack", "name": "Hosts", "site": "eve-ng-lab"},
            {"id": "clab-rack", "name": "Containerlab Devices", "site": "containerlab-vm"},
        ]

        client.get_device_locations.return_value = {
            "R1": {"rack": "core-rack"},
            "R2": {"rack": "core-rack"},
            "R3": {"rack": "core-rack"},
            "R4": {"rack": "core-rack"},
            "Switch-R1": {"rack": "switch-rack"},
            "Alpine-1": {"rack": "host-rack"},
        }

        return client

    @pytest.fixture
    def provider_with_netbox(self, mock_netbox_client):
        """Create a provider with mocked NetBox"""
        from config import hierarchy
        hierarchy._provider = None  # Reset singleton

        provider = HierarchyProvider()
        provider._use_netbox = True
        provider._netbox_available = True
        provider._netbox_client = mock_netbox_client

        yield provider
        hierarchy._provider = None  # Cleanup

    def test_netbox_get_data_source(self, provider_with_netbox):
        """NetBox mode returns 'netbox' as data source"""
        assert provider_with_netbox.get_data_source() == "netbox"

    def test_netbox_get_regions(self, provider_with_netbox, mock_netbox_client):
        """get_regions fetches from NetBox"""
        regions = provider_with_netbox.get_regions()
        mock_netbox_client.get_regions.assert_called_once()
        assert len(regions) == 2
        assert regions[0]["id"] == "us-west"

    def test_netbox_get_sites(self, provider_with_netbox, mock_netbox_client):
        """get_sites fetches from NetBox"""
        sites = provider_with_netbox.get_sites()
        mock_netbox_client.get_sites.assert_called_once()
        assert len(sites) == 2
        assert sites[0]["id"] == "eve-ng-lab"

    def test_netbox_get_racks(self, provider_with_netbox, mock_netbox_client):
        """get_racks fetches from NetBox"""
        racks = provider_with_netbox.get_racks()
        mock_netbox_client.get_locations.assert_called_once()
        assert len(racks) == 4

    def test_netbox_get_device_locations(self, provider_with_netbox, mock_netbox_client):
        """get_device_locations fetches from NetBox"""
        locations = provider_with_netbox.get_device_locations()
        mock_netbox_client.get_device_locations.assert_called_once()
        assert "R1" in locations
        assert locations["R1"]["rack"] == "core-rack"

    def test_netbox_get_hierarchy_tree(self, provider_with_netbox):
        """get_hierarchy_tree builds tree from NetBox data"""
        tree = provider_with_netbox.get_hierarchy_tree()
        assert "regions" in tree
        assert len(tree["regions"]) == 2

        # Check US West region
        us_west = next(r for r in tree["regions"] if r["id"] == "us-west")
        assert len(us_west["sites"]) == 1
        assert us_west["sites"][0]["id"] == "eve-ng-lab"

    def test_netbox_get_device_hierarchy(self, provider_with_netbox):
        """get_device_hierarchy returns correct path"""
        hierarchy = provider_with_netbox.get_device_hierarchy("R1")
        assert hierarchy is not None
        assert hierarchy["region"] == "us-west"
        assert hierarchy["site"] == "eve-ng-lab"
        assert hierarchy["rack"] == "core-rack"

    def test_netbox_get_devices_in_rack(self, provider_with_netbox):
        """get_devices_in_rack returns correct devices from NetBox"""
        devices = provider_with_netbox.get_devices_in_rack("core-rack")
        assert "R1" in devices
        assert "R2" in devices


# =============================================================================
# Provider Tests - Fallback Behavior
# =============================================================================

class TestHierarchyProviderFallback:
    """Tests for fallback behavior when NetBox fails"""

    @pytest.fixture
    def provider_with_failing_netbox(self):
        """Create a provider with a NetBox client that raises exceptions"""
        from config import hierarchy
        hierarchy._provider = None

        client = Mock()
        client.get_regions.side_effect = Exception("NetBox connection failed")
        client.get_sites.side_effect = Exception("NetBox connection failed")
        client.get_locations.side_effect = Exception("NetBox connection failed")
        client.get_device_locations.side_effect = Exception("NetBox connection failed")

        provider = HierarchyProvider()
        provider._use_netbox = True
        provider._netbox_available = True
        provider._netbox_client = client

        yield provider
        hierarchy._provider = None

    def test_fallback_get_regions_on_error(self, provider_with_failing_netbox):
        """Falls back to static REGIONS when NetBox fails"""
        regions = provider_with_failing_netbox.get_regions()
        assert regions == REGIONS

    def test_fallback_get_sites_on_error(self, provider_with_failing_netbox):
        """Falls back to static SITES when NetBox fails"""
        sites = provider_with_failing_netbox.get_sites()
        assert sites == SITES

    def test_fallback_get_racks_on_error(self, provider_with_failing_netbox):
        """Falls back to static RACKS when NetBox fails"""
        racks = provider_with_failing_netbox.get_racks()
        assert racks == RACKS

    def test_fallback_get_device_locations_on_error(self, provider_with_failing_netbox):
        """Falls back to static DEVICE_LOCATIONS when NetBox fails"""
        locations = provider_with_failing_netbox.get_device_locations()
        assert locations == DEVICE_LOCATIONS


# =============================================================================
# Singleton Tests
# =============================================================================

class TestHierarchyProviderSingleton:
    """Tests for the provider singleton pattern"""

    def test_get_hierarchy_provider_returns_same_instance(self):
        """get_hierarchy_provider returns the same instance"""
        from config import hierarchy
        hierarchy._provider = None  # Reset

        provider1 = get_hierarchy_provider()
        provider2 = get_hierarchy_provider()
        assert provider1 is provider2

        hierarchy._provider = None  # Cleanup


# =============================================================================
# NetBox Client Integration Tests (requires running NetBox)
# =============================================================================

class TestNetBoxClientHierarchy:
    """Integration tests for NetBox client hierarchy methods"""

    @pytest.fixture
    def netbox_available(self):
        """Skip if NetBox is not available"""
        try:
            from config.netbox_client import is_netbox_available
            if not is_netbox_available():
                pytest.skip("NetBox not available")
        except ImportError:
            pytest.skip("NetBox client not installed")
        except Exception:
            pytest.skip("NetBox connection failed")

    def test_netbox_get_regions(self, netbox_available):
        """NetBox client can fetch regions"""
        from config.netbox_client import get_client
        client = get_client()
        regions = client.get_regions()
        # After populate_netbox.py runs, we should have 2 regions
        assert isinstance(regions, list)

    def test_netbox_get_sites(self, netbox_available):
        """NetBox client can fetch sites"""
        from config.netbox_client import get_client
        client = get_client()
        sites = client.get_sites()
        assert isinstance(sites, list)

    def test_netbox_get_locations(self, netbox_available):
        """NetBox client can fetch locations"""
        from config.netbox_client import get_client
        client = get_client()
        locations = client.get_locations()
        assert isinstance(locations, list)

    def test_netbox_get_device_locations(self, netbox_available):
        """NetBox client can fetch device locations"""
        from config.netbox_client import get_client
        client = get_client()
        device_locations = client.get_device_locations()
        assert isinstance(device_locations, dict)

    def test_netbox_get_hierarchy_data(self, netbox_available):
        """NetBox client can fetch complete hierarchy data"""
        from config.netbox_client import get_client
        client = get_client()
        data = client.get_hierarchy_data()
        assert "regions" in data
        assert "sites" in data
        assert "racks" in data
        assert "device_locations" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
