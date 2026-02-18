"""
Hierarchical Site View Data Model

4-level hierarchy: Region -> Site -> Rack -> Device

Used by the dashboard topology view when ENABLE_HIERARCHICAL_VIEW=true.

Data Source Priority:
1. NetBox (if USE_NETBOX=true and NetBox is available)
2. Static configuration (fallback)
"""

import logging
import os
from typing import Dict, List, Optional, TypedDict

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Configuration
USE_NETBOX = os.getenv("USE_NETBOX", "false").lower() == "true"


class Region(TypedDict):
    id: str
    name: str


class Site(TypedDict):
    id: str
    name: str
    region: str


class Rack(TypedDict):
    id: str
    name: str
    site: str


class DeviceLocation(TypedDict):
    rack: str


# =============================================================================
# REGIONS
# =============================================================================
REGIONS: List[Region] = [
    {"id": "us-west", "name": "US West"},
    {"id": "containerlab", "name": "Containerlab"},
]

# =============================================================================
# SITES
# =============================================================================
SITES: List[Site] = [
    {"id": "eve-ng-lab", "name": "EVE-NG Lab", "region": "us-west"},
    {"id": "containerlab-vm", "name": "Containerlab VM", "region": "containerlab"},
]

# =============================================================================
# RACKS
# =============================================================================
RACKS: List[Rack] = [
    # EVE-NG Lab racks
    {"id": "core-rack", "name": "Core Routers", "site": "eve-ng-lab"},
    {"id": "switch-rack", "name": "Switches", "site": "eve-ng-lab"},
    {"id": "host-rack", "name": "Hosts", "site": "eve-ng-lab"},
    # Containerlab racks
    {"id": "clab-rack", "name": "Containerlab Devices", "site": "containerlab-vm"},
]

# =============================================================================
# DEVICE LOCATIONS
# =============================================================================
DEVICE_LOCATIONS: Dict[str, DeviceLocation] = {
    # Core routers (EVE-NG)
    "R1": {"rack": "core-rack"},
    "R2": {"rack": "core-rack"},
    "R3": {"rack": "core-rack"},
    "R4": {"rack": "core-rack"},
    "R6": {"rack": "core-rack"},
    "R7": {"rack": "core-rack"},
    # Switches (EVE-NG)
    "Switch-R1": {"rack": "switch-rack"},
    "Switch-R2": {"rack": "switch-rack"},
    "Switch-R4": {"rack": "switch-rack"},
    # Hosts (EVE-NG)
    "Alpine-1": {"rack": "host-rack"},
    "Docker-1": {"rack": "host-rack"},
    # Containerlab devices
    "edge1": {"rack": "clab-rack"},
    "spine1": {"rack": "clab-rack"},
    "R9": {"rack": "clab-rack"},
    "R10": {"rack": "clab-rack"},
    "server1": {"rack": "clab-rack"},
    "server2": {"rack": "clab-rack"},
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_rack_by_id(rack_id: str) -> Optional[Rack]:
    """Get rack by ID."""
    for rack in RACKS:
        if rack["id"] == rack_id:
            return rack
    return None


def get_site_by_id(site_id: str) -> Optional[Site]:
    """Get site by ID."""
    for site in SITES:
        if site["id"] == site_id:
            return site
    return None


def get_region_by_id(region_id: str) -> Optional[Region]:
    """Get region by ID."""
    for region in REGIONS:
        if region["id"] == region_id:
            return region
    return None


def get_device_hierarchy(device_name: str) -> Optional[Dict]:
    """
    Get full hierarchy path for a device.

    Returns dict with region, site, rack info or None if device not found.
    """
    location = DEVICE_LOCATIONS.get(device_name)
    if not location:
        return None

    rack = get_rack_by_id(location["rack"])
    if not rack:
        return None

    site = get_site_by_id(rack["site"])
    if not site:
        return None

    region = get_region_by_id(site["region"])
    if not region:
        return None

    return {
        "region": region["id"],
        "region_name": region["name"],
        "site": site["id"],
        "site_name": site["name"],
        "rack": rack["id"],
        "rack_name": rack["name"],
    }


def get_hierarchy_tree() -> Dict:
    """
    Build the full hierarchy tree for the API response.

    Returns nested structure: regions -> sites -> racks -> device_count
    """
    # Count devices per rack
    rack_device_counts: Dict[str, int] = {}
    for device_name, location in DEVICE_LOCATIONS.items():
        rack_id = location["rack"]
        rack_device_counts[rack_id] = rack_device_counts.get(rack_id, 0) + 1

    # Build tree structure
    tree = {
        "regions": []
    }

    for region in REGIONS:
        region_data = {
            "id": region["id"],
            "name": region["name"],
            "sites": []
        }

        for site in SITES:
            if site["region"] == region["id"]:
                site_data = {
                    "id": site["id"],
                    "name": site["name"],
                    "racks": []
                }

                for rack in RACKS:
                    if rack["site"] == site["id"]:
                        rack_data = {
                            "id": rack["id"],
                            "name": rack["name"],
                            "device_count": rack_device_counts.get(rack["id"], 0)
                        }
                        site_data["racks"].append(rack_data)

                region_data["sites"].append(site_data)

        tree["regions"].append(region_data)

    return tree


def get_devices_in_rack(rack_id: str) -> List[str]:
    """Get list of device names in a rack."""
    return [
        device_name
        for device_name, location in DEVICE_LOCATIONS.items()
        if location["rack"] == rack_id
    ]


def get_devices_in_site(site_id: str) -> List[str]:
    """Get list of device names in a site (all racks)."""
    devices = []
    for rack in RACKS:
        if rack["site"] == site_id:
            devices.extend(get_devices_in_rack(rack["id"]))
    return devices


def get_devices_in_region(region_id: str) -> List[str]:
    """Get list of device names in a region (all sites)."""
    devices = []
    for site in SITES:
        if site["region"] == region_id:
            devices.extend(get_devices_in_site(site["id"]))
    return devices


# =============================================================================
# HIERARCHY PROVIDER (NetBox Integration)
# =============================================================================

class HierarchyProvider:
    """
    Provider abstraction for hierarchy data.

    Attempts to fetch data from NetBox when USE_NETBOX=true.
    Falls back to static configuration when NetBox is unavailable.
    """

    def __init__(self):
        self._netbox_client = None
        self._use_netbox = USE_NETBOX
        self._netbox_available = None  # Cache availability check

    def _get_netbox_client(self):
        """Lazy-load NetBox client."""
        if self._netbox_client is None and self._use_netbox:
            try:
                from config.netbox_client import get_client, is_netbox_available

                if is_netbox_available():
                    self._netbox_client = get_client()
                    self._netbox_available = True
                    logger.info("Using NetBox as hierarchy data source")
                else:
                    self._netbox_available = False
                    logger.warning("NetBox not available, using static hierarchy")
            except ImportError:
                self._netbox_available = False
                logger.warning("NetBox client not installed, using static hierarchy")
            except Exception as e:
                self._netbox_available = False
                logger.warning(f"NetBox connection failed: {e}, using static hierarchy")

        return self._netbox_client

    def _is_netbox_available(self) -> bool:
        """Check if NetBox is available and configured."""
        if self._netbox_available is not None:
            return self._netbox_available

        self._get_netbox_client()
        return self._netbox_available or False

    def get_regions(self) -> List[Region]:
        """Get regions from NetBox or static config."""
        if self._is_netbox_available():
            try:
                client = self._get_netbox_client()
                netbox_regions = client.get_regions()
                return [{"id": r["id"], "name": r["name"]} for r in netbox_regions]
            except Exception as e:
                logger.error(f"Failed to get regions from NetBox: {e}")

        return REGIONS

    def get_sites(self) -> List[Site]:
        """Get sites from NetBox or static config."""
        if self._is_netbox_available():
            try:
                client = self._get_netbox_client()
                netbox_sites = client.get_sites()
                return [
                    {"id": s["id"], "name": s["name"], "region": s["region"] or ""}
                    for s in netbox_sites
                ]
            except Exception as e:
                logger.error(f"Failed to get sites from NetBox: {e}")

        return SITES

    def get_racks(self) -> List[Rack]:
        """Get racks (locations) from NetBox or static config."""
        if self._is_netbox_available():
            try:
                client = self._get_netbox_client()
                netbox_locations = client.get_locations()
                return [
                    {"id": loc["id"], "name": loc["name"], "site": loc["site"] or ""}
                    for loc in netbox_locations
                ]
            except Exception as e:
                logger.error(f"Failed to get locations from NetBox: {e}")

        return RACKS

    def get_device_locations(self) -> Dict[str, DeviceLocation]:
        """Get device-to-rack mapping from NetBox or static config."""
        if self._is_netbox_available():
            try:
                client = self._get_netbox_client()
                return client.get_device_locations()
            except Exception as e:
                logger.error(f"Failed to get device locations from NetBox: {e}")

        return DEVICE_LOCATIONS

    def get_rack_by_id(self, rack_id: str) -> Optional[Rack]:
        """Get rack by ID."""
        for rack in self.get_racks():
            if rack["id"] == rack_id:
                return rack
        return None

    def get_site_by_id(self, site_id: str) -> Optional[Site]:
        """Get site by ID."""
        for site in self.get_sites():
            if site["id"] == site_id:
                return site
        return None

    def get_region_by_id(self, region_id: str) -> Optional[Region]:
        """Get region by ID."""
        for region in self.get_regions():
            if region["id"] == region_id:
                return region
        return None

    def get_device_hierarchy(self, device_name: str) -> Optional[Dict]:
        """Get full hierarchy path for a device."""
        device_locations = self.get_device_locations()
        location = device_locations.get(device_name)
        if not location:
            return None

        rack = self.get_rack_by_id(location["rack"])
        if not rack:
            return None

        site = self.get_site_by_id(rack["site"])
        if not site:
            return None

        region = self.get_region_by_id(site["region"])
        if not region:
            return None

        return {
            "region": region["id"],
            "region_name": region["name"],
            "site": site["id"],
            "site_name": site["name"],
            "rack": rack["id"],
            "rack_name": rack["name"],
        }

    def get_hierarchy_tree(self) -> Dict:
        """Build the full hierarchy tree."""
        regions = self.get_regions()
        sites = self.get_sites()
        racks = self.get_racks()
        device_locations = self.get_device_locations()

        # Count devices per rack
        rack_device_counts: Dict[str, int] = {}
        for device_name, location in device_locations.items():
            rack_id = location["rack"]
            rack_device_counts[rack_id] = rack_device_counts.get(rack_id, 0) + 1

        # Build tree structure
        tree = {"regions": []}

        for region in regions:
            region_data = {
                "id": region["id"],
                "name": region["name"],
                "sites": [],
            }

            for site in sites:
                if site["region"] == region["id"]:
                    site_data = {
                        "id": site["id"],
                        "name": site["name"],
                        "racks": [],
                    }

                    for rack in racks:
                        if rack["site"] == site["id"]:
                            rack_data = {
                                "id": rack["id"],
                                "name": rack["name"],
                                "device_count": rack_device_counts.get(rack["id"], 0),
                            }
                            site_data["racks"].append(rack_data)

                    region_data["sites"].append(site_data)

            tree["regions"].append(region_data)

        return tree

    def get_devices_in_rack(self, rack_id: str) -> List[str]:
        """Get list of device names in a rack."""
        device_locations = self.get_device_locations()
        return [
            device_name
            for device_name, location in device_locations.items()
            if location["rack"] == rack_id
        ]

    def get_devices_in_site(self, site_id: str) -> List[str]:
        """Get list of device names in a site (all racks)."""
        devices = []
        for rack in self.get_racks():
            if rack["site"] == site_id:
                devices.extend(self.get_devices_in_rack(rack["id"]))
        return devices

    def get_devices_in_region(self, region_id: str) -> List[str]:
        """Get list of device names in a region (all sites)."""
        devices = []
        for site in self.get_sites():
            if site["region"] == region_id:
                devices.extend(self.get_devices_in_site(site["id"]))
        return devices

    def get_data_source(self) -> str:
        """Return current data source name."""
        if self._is_netbox_available():
            return "netbox"
        return "static"

    def refresh(self):
        """Refresh cached data from NetBox."""
        if self._netbox_client:
            self._netbox_client.refresh_cache()


# Singleton instance
_provider: Optional[HierarchyProvider] = None


def get_hierarchy_provider() -> HierarchyProvider:
    """Get or create the hierarchy provider singleton."""
    global _provider
    if _provider is None:
        _provider = HierarchyProvider()
    return _provider