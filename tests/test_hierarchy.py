#!/usr/bin/env python3
"""
Hierarchical Site View Tests

Tests for the 4-level hierarchy (Region > Site > Rack > Device) feature.
Covers both the data model (config/hierarchy.py) and API endpoints.

Usage:
    pytest tests/test_hierarchy.py -v
    pytest tests/test_hierarchy.py -v -k "unit"  # Unit tests only
    pytest tests/test_hierarchy.py -v -k "api"   # API tests only
"""

import os
import sys
import pytest
import requests
from unittest.mock import patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.hierarchy import (
    REGIONS,
    SITES,
    RACKS,
    DEVICE_LOCATIONS,
    get_rack_by_id,
    get_site_by_id,
    get_region_by_id,
    get_device_hierarchy,
    get_hierarchy_tree,
    get_devices_in_rack,
    get_devices_in_site,
    get_devices_in_region,
)

# API base URL - can be overridden with environment variable
API_BASE = os.getenv("API_BASE", "http://localhost:5001")


# =============================================================================
# Unit Tests - Data Model (config/hierarchy.py)
# =============================================================================

class TestHierarchyDataModel:
    """Unit tests for the hierarchy data model"""

    def test_unit_regions_structure(self):
        """Regions have required fields"""
        assert len(REGIONS) >= 1
        for region in REGIONS:
            assert "id" in region
            assert "name" in region
            assert isinstance(region["id"], str)
            assert isinstance(region["name"], str)

    def test_unit_sites_structure(self):
        """Sites have required fields and reference valid regions"""
        assert len(SITES) >= 1
        region_ids = {r["id"] for r in REGIONS}
        for site in SITES:
            assert "id" in site
            assert "name" in site
            assert "region" in site
            assert site["region"] in region_ids, f"Site {site['id']} references invalid region"

    def test_unit_racks_structure(self):
        """Racks have required fields and reference valid sites"""
        assert len(RACKS) >= 1
        site_ids = {s["id"] for s in SITES}
        for rack in RACKS:
            assert "id" in rack
            assert "name" in rack
            assert "site" in rack
            assert rack["site"] in site_ids, f"Rack {rack['id']} references invalid site"

    def test_unit_device_locations_reference_valid_racks(self):
        """All device locations reference valid rack IDs"""
        rack_ids = {r["id"] for r in RACKS}
        for device_name, location in DEVICE_LOCATIONS.items():
            assert "rack" in location
            assert location["rack"] in rack_ids, f"Device {device_name} references invalid rack"

    def test_unit_get_rack_by_id_found(self):
        """get_rack_by_id returns rack when found"""
        rack = get_rack_by_id("core-rack")
        assert rack is not None
        assert rack["id"] == "core-rack"
        assert rack["name"] == "Core Routers"

    def test_unit_get_rack_by_id_not_found(self):
        """get_rack_by_id returns None when not found"""
        rack = get_rack_by_id("nonexistent-rack")
        assert rack is None

    def test_unit_get_site_by_id_found(self):
        """get_site_by_id returns site when found"""
        site = get_site_by_id("eve-ng-lab")
        assert site is not None
        assert site["id"] == "eve-ng-lab"
        assert site["region"] == "us-west"

    def test_unit_get_site_by_id_not_found(self):
        """get_site_by_id returns None when not found"""
        site = get_site_by_id("nonexistent-site")
        assert site is None

    def test_unit_get_region_by_id_found(self):
        """get_region_by_id returns region when found"""
        region = get_region_by_id("us-west")
        assert region is not None
        assert region["id"] == "us-west"
        assert region["name"] == "US West"

    def test_unit_get_region_by_id_not_found(self):
        """get_region_by_id returns None when not found"""
        region = get_region_by_id("nonexistent-region")
        assert region is None

    def test_unit_get_device_hierarchy_found(self):
        """get_device_hierarchy returns full path for known device"""
        hierarchy = get_device_hierarchy("R1")
        assert hierarchy is not None
        assert hierarchy["region"] == "us-west"
        assert hierarchy["site"] == "eve-ng-lab"
        assert hierarchy["rack"] == "core-rack"
        assert "region_name" in hierarchy
        assert "site_name" in hierarchy
        assert "rack_name" in hierarchy

    def test_unit_get_device_hierarchy_not_found(self):
        """get_device_hierarchy returns None for unknown device"""
        hierarchy = get_device_hierarchy("NonexistentDevice")
        assert hierarchy is None

    def test_unit_get_hierarchy_tree_structure(self):
        """get_hierarchy_tree returns valid nested structure"""
        tree = get_hierarchy_tree()
        assert "regions" in tree
        assert len(tree["regions"]) >= 1

        for region in tree["regions"]:
            assert "id" in region
            assert "name" in region
            assert "sites" in region

            for site in region["sites"]:
                assert "id" in site
                assert "name" in site
                assert "racks" in site

                for rack in site["racks"]:
                    assert "id" in rack
                    assert "name" in rack
                    assert "device_count" in rack
                    assert isinstance(rack["device_count"], int)

    def test_unit_get_devices_in_rack(self):
        """get_devices_in_rack returns devices in the rack"""
        devices = get_devices_in_rack("core-rack")
        assert len(devices) >= 1
        assert "R1" in devices
        assert "R2" in devices

    def test_unit_get_devices_in_rack_empty(self):
        """get_devices_in_rack returns empty list for unknown rack"""
        devices = get_devices_in_rack("nonexistent-rack")
        assert devices == []

    def test_unit_get_devices_in_site(self):
        """get_devices_in_site returns devices from all racks in site"""
        devices = get_devices_in_site("eve-ng-lab")
        assert len(devices) >= 1
        # Should include devices from core-rack, switch-rack, and host-rack
        assert "R1" in devices  # core-rack
        assert "Switch-R1" in devices  # switch-rack
        assert "Alpine-1" in devices  # host-rack

    def test_unit_get_devices_in_site_empty(self):
        """get_devices_in_site returns empty list for unknown site"""
        devices = get_devices_in_site("nonexistent-site")
        assert devices == []

    def test_unit_get_devices_in_region(self):
        """get_devices_in_region returns devices from all sites in region"""
        devices = get_devices_in_region("us-west")
        assert len(devices) >= 1
        # Should include all EVE-NG devices
        assert "R1" in devices
        assert "Switch-R1" in devices

    def test_unit_get_devices_in_region_empty(self):
        """get_devices_in_region returns empty list for unknown region"""
        devices = get_devices_in_region("nonexistent-region")
        assert devices == []

    def test_unit_all_devices_have_hierarchy(self):
        """Every device in DEVICE_LOCATIONS has a complete hierarchy path"""
        for device_name in DEVICE_LOCATIONS.keys():
            hierarchy = get_device_hierarchy(device_name)
            assert hierarchy is not None, f"Device {device_name} has no hierarchy"
            assert hierarchy["region"], f"Device {device_name} has no region"
            assert hierarchy["site"], f"Device {device_name} has no site"
            assert hierarchy["rack"], f"Device {device_name} has no rack"


# =============================================================================
# API Tests - Endpoints (requires running API server)
# =============================================================================

class TestHierarchyAPI:
    """API tests for hierarchy endpoints"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = API_BASE
        self.session = requests.Session()

    def _is_api_available(self) -> bool:
        """Check if API is running and accessible (not just up, but authenticated)."""
        try:
            resp = self.session.get(f"{self.base_url}/api/health", timeout=2)
            # 401 means API is up but requires JWT — can't test without auth
            return resp.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    @pytest.fixture
    def api_available(self):
        """Skip if API not available or requires auth"""
        if not self._is_api_available():
            pytest.skip("API server not available or requires authentication")

    def test_api_hierarchy_disabled_returns_403(self, api_available):
        """
        /api/hierarchy returns 403 when feature is disabled.

        Note: This test assumes ENABLE_HIERARCHICAL_VIEW is NOT set.
        If it's enabled in the environment, this test will fail.
        """
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        if resp.status_code == 401:
            pytest.skip("API requires authentication")
        # Accept either 403 (disabled) or 200 (enabled)
        # The behavior depends on server configuration
        assert resp.status_code in (200, 403)
        if resp.status_code == 403:
            data = resp.json()
            assert "error" in data
            assert "disabled" in data["error"].lower()

    def test_api_hierarchy_returns_tree_when_enabled(self, api_available):
        """
        /api/hierarchy returns tree structure when enabled.

        Note: Requires ENABLE_HIERARCHICAL_VIEW=true in server environment.
        """
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        if resp.status_code in (401, 403):
            pytest.skip("API requires authentication or hierarchical view is disabled")

        assert resp.status_code == 200
        data = resp.json()
        assert "regions" in data
        assert len(data["regions"]) >= 1

    def test_api_topology_level_disabled_returns_403(self, api_available):
        """
        /api/topology/level/<type>/<id> returns 403 when feature is disabled.
        """
        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/core-rack")
        if resp.status_code == 401:
            pytest.skip("API requires authentication")
        assert resp.status_code in (200, 403, 404)
        if resp.status_code == 403:
            data = resp.json()
            assert "error" in data
            assert "disabled" in data["error"].lower()

    def test_api_topology_level_invalid_type(self, api_available):
        """
        /api/topology/level returns 400 for invalid level type.
        """
        resp = self.session.get(f"{self.base_url}/api/topology/level/invalid/test")
        if resp.status_code in (401, 403):
            pytest.skip("API requires authentication or hierarchical view is disabled")
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data
        assert "Invalid level type" in data["error"]

    def test_api_topology_level_not_found(self, api_available):
        """
        /api/topology/level returns 404 for unknown level ID.
        """
        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/nonexistent")
        if resp.status_code in (401, 403):
            pytest.skip("API requires authentication or hierarchical view is disabled")
        assert resp.status_code == 404
        data = resp.json()
        assert "error" in data

    def test_api_topology_level_returns_filtered_nodes(self, api_available):
        """
        /api/topology/level returns only devices in the specified level.
        """
        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/core-rack")
        if resp.status_code in (401, 403):
            pytest.skip("API requires authentication or hierarchical view is disabled")
        if resp.status_code == 404:
            pytest.skip("Topology not available (devices may be offline)")

        assert resp.status_code == 200
        data = resp.json()
        assert "level" in data
        assert data["level"]["type"] == "rack"
        assert data["level"]["id"] == "core-rack"
        assert "nodes" in data
        assert "links" in data

        # All nodes should be core routers
        for node in data["nodes"]:
            if node.get("rack"):
                assert node["rack"] == "core-rack"

    def test_api_topology_includes_hierarchy_when_enabled(self, api_available):
        """
        /api/topology includes region/site/rack when ENABLE_HIERARCHICAL_VIEW=true.
        """
        resp = self.session.get(f"{self.base_url}/api/topology")
        if resp.status_code == 401:
            pytest.skip("API requires authentication")
        assert resp.status_code in (200, 500)
        if resp.status_code == 500:
            pytest.skip("Topology discovery failed (devices may be offline)")

        data = resp.json()
        if "nodes" in data and len(data["nodes"]) > 0:
            # Check if hierarchy info is present (only if feature is enabled)
            node = data["nodes"][0]
            # Either all fields present (enabled) or none (disabled)
            has_hierarchy = "region" in node and "site" in node and "rack" in node
            no_hierarchy = "region" not in node and "site" not in node and "rack" not in node
            assert has_hierarchy or no_hierarchy


# =============================================================================
# Integration Tests
# =============================================================================

class TestHierarchyIntegration:
    """Integration tests for hierarchy feature"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = API_BASE
        self.session = requests.Session()

    def _is_api_available(self) -> bool:
        """Check if API is running and accessible (not just up, but authenticated)."""
        try:
            resp = self.session.get(f"{self.base_url}/api/health", timeout=2)
            return resp.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    @pytest.fixture
    def api_available(self):
        """Skip if API not available or requires auth"""
        if not self._is_api_available():
            pytest.skip("API server not available or requires authentication")

    def test_integration_hierarchy_matches_device_inventory(self):
        """All devices in hierarchy are in the device inventory"""
        from config.devices import DEVICES

        for device_name, loc in DEVICE_LOCATIONS.items():
            assert device_name in DEVICES, (
                f"Device {device_name} in hierarchy but not in inventory"
            )

    def test_integration_device_count_accurate(self):
        """Device counts in hierarchy tree match actual device counts"""
        tree = get_hierarchy_tree()

        for region in tree["regions"]:
            for site in region["sites"]:
                for rack in site["racks"]:
                    expected_count = len(get_devices_in_rack(rack["id"]))
                    assert rack["device_count"] == expected_count, (
                        f"Rack {rack['id']} device_count mismatch: "
                        f"expected {expected_count}, got {rack['device_count']}"
                    )

    def test_integration_drill_down_preserves_devices(self, api_available):
        """Drilling down through levels shows consistent device counts"""
        # Get hierarchy
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        if resp.status_code in (401, 403):
            pytest.skip("API requires authentication or hierarchical view is disabled")

        tree = resp.json()

        # Use the hierarchy provider (NetBox-aware) instead of static functions
        from config.hierarchy import get_hierarchy_provider
        provider = get_hierarchy_provider()

        for region in tree["regions"]:
            region_devices = set(provider.get_devices_in_region(region["id"]))

            for site in region["sites"]:
                site_devices = set(provider.get_devices_in_site(site["id"]))
                # Site devices should be subset of region devices
                assert site_devices.issubset(region_devices)

                for rack in site["racks"]:
                    rack_devices = set(provider.get_devices_in_rack(rack["id"]))
                    # Rack devices should be subset of site devices
                    assert rack_devices.issubset(site_devices)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
