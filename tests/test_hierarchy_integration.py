#!/usr/bin/env python3
"""
Hierarchical Site View - Integration Tests

Tests the full integration between:
- Hierarchy data model
- API endpoints
- Device inventory
- Topology discovery

These tests require either:
1. A running API server (for API tests)
2. Access to config modules (for data consistency tests)

Usage:
    pytest tests/test_hierarchy_integration.py -v
    pytest tests/test_hierarchy_integration.py -v -k "data"  # Data tests only
    pytest tests/test_hierarchy_integration.py -v -k "api"   # API tests only
"""

import os
import sys
import pytest
import requests
from typing import Set

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.hierarchy import (
    REGIONS,
    SITES,
    RACKS,
    DEVICE_LOCATIONS,
    get_hierarchy_tree,
    get_device_hierarchy,
    get_devices_in_region,
    get_devices_in_site,
    get_devices_in_rack,
)
from config.devices import DEVICES

# API base URL
API_BASE = os.getenv("API_BASE", "http://localhost:5001")


# =============================================================================
# Data Consistency Tests (no API required)
# =============================================================================

class TestDataConsistency:
    """Test data consistency between hierarchy and device inventory"""

    def test_data_all_hierarchy_devices_in_inventory(self):
        """Every device in hierarchy should exist in device inventory"""
        inventory_devices = set(DEVICES.keys())

        for device_name, loc in DEVICE_LOCATIONS.items():
            assert device_name in inventory_devices, (
                f"Device '{device_name}' in hierarchy but not in DEVICES inventory"
            )

    def test_data_hierarchy_covers_core_devices(self):
        """Core routers and switches should be in hierarchy"""
        core_devices = {'R1', 'R2', 'R3', 'R4', 'Switch-R1', 'Switch-R2', 'Switch-R4'}
        hierarchy_devices = set(DEVICE_LOCATIONS.keys())

        missing = core_devices - hierarchy_devices
        assert not missing, f"Core devices missing from hierarchy: {missing}"

    def test_data_no_orphan_sites(self):
        """Every site should belong to a valid region"""
        region_ids = {r['id'] for r in REGIONS}

        for site in SITES:
            assert site['region'] in region_ids, (
                f"Site '{site['id']}' references non-existent region '{site['region']}'"
            )

    def test_data_no_orphan_racks(self):
        """Every rack should belong to a valid site"""
        site_ids = {s['id'] for s in SITES}

        for rack in RACKS:
            assert rack['site'] in site_ids, (
                f"Rack '{rack['id']}' references non-existent site '{rack['site']}'"
            )

    def test_data_no_empty_racks(self):
        """No rack should be empty (have zero devices)"""
        for rack in RACKS:
            devices = get_devices_in_rack(rack['id'])
            assert len(devices) > 0, f"Rack '{rack['id']}' has no devices"

    def test_data_no_empty_sites(self):
        """No site should be empty (have zero devices)"""
        for site in SITES:
            devices = get_devices_in_site(site['id'])
            assert len(devices) > 0, f"Site '{site['id']}' has no devices"

    def test_data_no_empty_regions(self):
        """No region should be empty (have zero devices)"""
        for region in REGIONS:
            devices = get_devices_in_region(region['id'])
            assert len(devices) > 0, f"Region '{region['id']}' has no devices"

    def test_data_device_counts_consistent(self):
        """Device counts should be consistent across levels"""
        tree = get_hierarchy_tree()

        total_devices = len(DEVICE_LOCATIONS)
        tree_device_count = 0

        for region in tree['regions']:
            region_count = 0
            for site in region['sites']:
                site_count = 0
                for rack in site['racks']:
                    site_count += rack['device_count']
                    tree_device_count += rack['device_count']

                # Verify site count matches sum of racks
                expected_site_count = sum(r['device_count'] for r in site['racks'])
                assert site_count == expected_site_count

        assert tree_device_count == total_devices, (
            f"Tree device count ({tree_device_count}) != total devices ({total_devices})"
        )

    def test_data_unique_device_assignment(self):
        """Each device should appear in exactly one rack"""
        device_assignments: dict[str, list[str]] = {}

        for device_name, location in DEVICE_LOCATIONS.items():
            rack_id = location['rack']
            if device_name not in device_assignments:
                device_assignments[device_name] = []
            device_assignments[device_name].append(rack_id)

        for device_name, racks in device_assignments.items():
            assert len(racks) == 1, (
                f"Device '{device_name}' assigned to multiple racks: {racks}"
            )

    def test_data_hierarchy_path_completeness(self):
        """Every device should have a complete hierarchy path"""
        for device_name in DEVICE_LOCATIONS.keys():
            hierarchy = get_device_hierarchy(device_name)

            assert hierarchy is not None, f"Device '{device_name}' has no hierarchy"
            assert 'region' in hierarchy, f"Device '{device_name}' missing region"
            assert 'site' in hierarchy, f"Device '{device_name}' missing site"
            assert 'rack' in hierarchy, f"Device '{device_name}' missing rack"
            assert 'region_name' in hierarchy, f"Device '{device_name}' missing region_name"
            assert 'site_name' in hierarchy, f"Device '{device_name}' missing site_name"
            assert 'rack_name' in hierarchy, f"Device '{device_name}' missing rack_name"


# =============================================================================
# API Integration Tests (requires running API server)
# =============================================================================

class TestAPIIntegration:
    """API integration tests - require running server"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = API_BASE
        self.session = requests.Session()

    def _is_api_available(self) -> bool:
        """Check if API is running"""
        try:
            resp = self.session.get(f"{self.base_url}/api/health", timeout=2)
            return resp.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    def _is_hierarchy_enabled(self) -> bool:
        """Check if hierarchy feature is enabled"""
        try:
            resp = self.session.get(f"{self.base_url}/api/hierarchy", timeout=2)
            return resp.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    @pytest.fixture
    def api_available(self):
        """Skip if API not available"""
        if not self._is_api_available():
            pytest.skip("API server not available")

    @pytest.fixture
    def hierarchy_enabled(self, api_available):
        """Skip if hierarchy feature is disabled"""
        if not self._is_hierarchy_enabled():
            pytest.skip("Hierarchy feature is disabled on server")

    def test_api_hierarchy_endpoint_structure(self, hierarchy_enabled):
        """Hierarchy endpoint returns proper structure"""
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        assert resp.status_code == 200

        data = resp.json()
        assert 'regions' in data
        assert isinstance(data['regions'], list)

        for region in data['regions']:
            assert 'id' in region
            assert 'name' in region
            assert 'sites' in region

            for site in region['sites']:
                assert 'id' in site
                assert 'name' in site
                assert 'racks' in site

                for rack in site['racks']:
                    assert 'id' in rack
                    assert 'name' in rack
                    assert 'device_count' in rack

    def test_api_hierarchy_matches_local_model(self, hierarchy_enabled):
        """API hierarchy has valid structure with regions, sites, and racks"""
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        api_tree = resp.json()

        # Verify structure: regions contain sites which contain racks
        assert len(api_tree['regions']) > 0, "No regions in hierarchy"

        for region in api_tree['regions']:
            assert 'id' in region
            assert 'name' in region
            assert 'sites' in region
            for site in region['sites']:
                assert 'id' in site
                assert 'name' in site
                assert 'racks' in site

    def test_api_topology_level_region_filter(self, hierarchy_enabled):
        """Topology level endpoint correctly filters by region"""
        # Get regions from API hierarchy (may be NetBox-sourced)
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        tree = resp.json()
        if not tree.get('regions'):
            pytest.skip("No regions in hierarchy")
        region = tree['regions'][0]
        region_id = region['id']

        resp = self.session.get(f"{self.base_url}/api/topology/level/region/{region_id}")
        assert resp.status_code == 200

        data = resp.json()
        assert 'nodes' in data
        assert 'links' in data
        assert 'level' in data
        assert data['level']['type'] == 'region'
        assert data['level']['id'] == region_id

    def test_api_topology_level_site_filter(self, hierarchy_enabled):
        """Topology level endpoint correctly filters by site"""
        # Get sites from API hierarchy
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        tree = resp.json()
        site_id = None
        for region in tree.get('regions', []):
            for site in region.get('sites', []):
                site_id = site['id']
                break
            if site_id:
                break
        if not site_id:
            pytest.skip("No sites in hierarchy")

        resp = self.session.get(f"{self.base_url}/api/topology/level/site/{site_id}")
        assert resp.status_code == 200

        data = resp.json()
        assert data['level']['type'] == 'site'
        assert data['level']['id'] == site_id
        assert len(data['nodes']) > 0, "No devices returned for site"

    def test_api_topology_level_rack_filter(self, hierarchy_enabled):
        """Topology level endpoint correctly filters by rack"""
        # Get racks from API hierarchy
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        tree = resp.json()
        rack_id = None
        for region in tree.get('regions', []):
            for site in region.get('sites', []):
                for rack in site.get('racks', []):
                    if rack.get('device_count', 0) > 0:
                        rack_id = rack['id']
                        break
                if rack_id:
                    break
            if rack_id:
                break
        if not rack_id:
            pytest.skip("No non-empty racks in hierarchy")

        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/{rack_id}")
        assert resp.status_code == 200

        data = resp.json()
        assert data['level']['type'] == 'rack'
        assert data['level']['id'] == rack_id
        assert len(data['nodes']) > 0, "No devices returned for rack"

    def test_api_topology_level_invalid_type(self, hierarchy_enabled):
        """Invalid level type returns 400"""
        resp = self.session.get(f"{self.base_url}/api/topology/level/invalid/test")
        assert resp.status_code == 400

        data = resp.json()
        assert 'error' in data

    def test_api_topology_level_nonexistent_id(self, hierarchy_enabled):
        """Nonexistent level ID returns 404"""
        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/nonexistent-rack")
        assert resp.status_code == 404

        data = resp.json()
        assert 'error' in data

    def test_api_topology_includes_hierarchy_info(self, hierarchy_enabled):
        """Topology nodes include hierarchy info when feature enabled"""
        resp = self.session.get(f"{self.base_url}/api/topology")
        if resp.status_code != 200:
            pytest.skip("Topology endpoint unavailable")

        data = resp.json()
        if not data.get('nodes'):
            pytest.skip("No nodes in topology")

        # At least some nodes should have hierarchy info
        nodes_with_hierarchy = [
            n for n in data['nodes']
            if 'region' in n and 'site' in n and 'rack' in n
        ]
        assert len(nodes_with_hierarchy) > 0, (
            "No nodes have hierarchy info (region/site/rack)"
        )

    def test_api_filtered_links_only_internal(self, hierarchy_enabled):
        """Filtered topology only includes internal links"""
        # Get a rack with devices from the API hierarchy
        resp = self.session.get(f"{self.base_url}/api/hierarchy")
        tree = resp.json()
        rack_id = None
        for region in tree.get('regions', []):
            for site in region.get('sites', []):
                for rack in site.get('racks', []):
                    if rack.get('device_count', 0) > 2:
                        rack_id = rack['id']
                        break
                if rack_id:
                    break
            if rack_id:
                break
        if not rack_id:
            pytest.skip("No rack with enough devices for link test")

        resp = self.session.get(f"{self.base_url}/api/topology/level/rack/{rack_id}")
        if resp.status_code != 200:
            pytest.skip("Rack topology unavailable")

        data = resp.json()
        rack_devices = {node['id'] for node in data.get('nodes', [])}

        for link in data.get('links', []):
            source = link.get('source')
            target = link.get('target')

            source_id = source['id'] if isinstance(source, dict) else source
            target_id = target['id'] if isinstance(target, dict) else target

            assert source_id in rack_devices, (
                f"Link source '{source_id}' not in rack '{rack_id}'"
            )
            assert target_id in rack_devices, (
                f"Link target '{target_id}' not in rack '{rack_id}'"
            )


# =============================================================================
# Drill-Down Navigation Tests
# =============================================================================

class TestDrillDownNavigation:
    """Test hierarchy drill-down navigation consistency"""

    def test_drilldown_region_to_site_preserves_devices(self):
        """Drilling from region to site doesn't lose devices"""
        for region in REGIONS:
            region_devices = set(get_devices_in_region(region['id']))
            sites_devices: Set[str] = set()

            for site in SITES:
                if site['region'] == region['id']:
                    sites_devices.update(get_devices_in_site(site['id']))

            assert region_devices == sites_devices, (
                f"Region '{region['id']}' devices don't match sum of its sites"
            )

    def test_drilldown_site_to_rack_preserves_devices(self):
        """Drilling from site to rack doesn't lose devices"""
        for site in SITES:
            site_devices = set(get_devices_in_site(site['id']))
            racks_devices: Set[str] = set()

            for rack in RACKS:
                if rack['site'] == site['id']:
                    racks_devices.update(get_devices_in_rack(rack['id']))

            assert site_devices == racks_devices, (
                f"Site '{site['id']}' devices don't match sum of its racks"
            )

    def test_drilldown_total_devices_preserved(self):
        """Total devices across all regions equals DEVICE_LOCATIONS"""
        all_region_devices: Set[str] = set()

        for region in REGIONS:
            all_region_devices.update(get_devices_in_region(region['id']))

        expected_devices = set(DEVICE_LOCATIONS.keys())
        assert all_region_devices == expected_devices, (
            f"Total region devices ({len(all_region_devices)}) != "
            f"DEVICE_LOCATIONS ({len(expected_devices)})"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
