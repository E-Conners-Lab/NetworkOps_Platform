"""
NetBox API client module.

Provides a caching client for NetBox that returns device data in the same format
as the static DEVICES dict for compatibility with existing code.

Includes circuit breaker protection to handle NetBox unavailability gracefully.
"""

import logging
import os
import time
from functools import lru_cache
from typing import Any

import pynetbox
from dotenv import load_dotenv

from core.circuit_breaker import get_circuit_breaker, CircuitOpenError

load_dotenv()

logger = logging.getLogger(__name__)

# NetBox configuration
NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000")
NETBOX_API_TOKEN = os.getenv("NETBOX_API_TOKEN", "")
NETBOX_CACHE_TTL = int(os.getenv("NETBOX_CACHE_TTL", "300"))  # 5 minutes default
NETBOX_TENANT = os.getenv("NETBOX_TENANT", "")  # Filter devices by tenant slug (e.g., "core-lab")

# Device type mapping: NetBox custom_field -> Netmiko device_type
DEVICE_TYPE_MAP = {
    # Cisco
    "cisco_xe": "cisco_xe",
    # Juniper
    "juniper_junos": "juniper_junos",
    # HPE
    "aruba_aoscx": "aruba_aoscx",
    "hp_procurve": "hp_procurve",
    "hp_comware": "hp_comware",
    # Linux
    "linux": "linux",
    # Containerlab
    "containerlab_srlinux": "containerlab_srlinux",
    "containerlab_frr": "containerlab_frr",
    "containerlab_linux": "containerlab_linux",
}


class NetBoxClient:
    """NetBox API client with caching and circuit breaker protection."""

    def __init__(
        self,
        url: str = NETBOX_URL,
        token: str = None,
        cache_ttl: int = NETBOX_CACHE_TTL,
        tenant: str = NETBOX_TENANT,
    ):
        """Initialize NetBox client.

        Args:
            url: NetBox URL
            token: API token (resolved via SecretsManager if None)
            cache_ttl: Cache time-to-live in seconds
            tenant: Tenant slug to filter devices (e.g., "core-lab")
        """
        if token is None:
            from config.vault_client import get_netbox_token
            token = get_netbox_token()
        self.url = url
        self.token = token
        self.cache_ttl = cache_ttl
        self.tenant = tenant
        self._api = None
        self._cache = {}
        self._cache_timestamps = {}

        # Circuit breaker for NetBox API calls
        self._circuit_breaker = get_circuit_breaker(
            "netbox",
            failure_threshold=3,
            recovery_timeout=60,
        )

    @property
    def api(self) -> pynetbox.api:
        """Lazy-load pynetbox API client."""
        if self._api is None:
            self._api = pynetbox.api(self.url, token=self.token)
            self._api.http_session.verify = os.getenv("NETBOX_VERIFY_SSL", "false").lower() == "true"
            if not self._api.http_session.verify:
                logger.warning("NetBox SSL verification disabled. Set NETBOX_VERIFY_SSL=true for production.")
        return self._api

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cache entry is still valid."""
        if key not in self._cache_timestamps:
            return False
        return (time.time() - self._cache_timestamps[key]) < self.cache_ttl

    def _get_cached(self, key: str) -> Any | None:
        """Get value from cache if valid."""
        if self._is_cache_valid(key):
            return self._cache.get(key)
        return None

    def _set_cached(self, key: str, value: Any) -> None:
        """Set value in cache."""
        self._cache[key] = value
        self._cache_timestamps[key] = time.time()

    def refresh_cache(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        self._cache_timestamps.clear()

    def _get_all_devices(self):
        """Get all devices, filtered by tenant if configured.

        Returns cached data if circuit breaker is open.
        """
        if not self._circuit_breaker.allow_request():
            # Circuit is open - return cached data or empty list
            cached = self._get_cached("devices_raw")
            if cached is not None:
                logger.warning("NetBox circuit open, returning cached device list")
                return cached
            logger.warning("NetBox circuit open and no cached data available")
            return []

        try:
            if self.tenant:
                result = list(self.api.dcim.devices.filter(tenant=self.tenant))
            else:
                result = list(self.api.dcim.devices.all())

            # Cache raw device list for fallback
            self._set_cached("devices_raw", result)
            self._circuit_breaker.record_success()
            return result
        except Exception as e:
            logger.error(f"NetBox API call failed: {e}")
            self._circuit_breaker.record_failure()

            # Return cached data on failure
            cached = self._get_cached("devices_raw")
            if cached is not None:
                logger.info("Returning cached device list after failure")
                return cached
            raise

    def get_devices(self) -> dict[str, dict]:
        """Get all devices in DEVICES dict format.

        Returns:
            Dict matching the format of config/devices.py DEVICES
        """
        cached = self._get_cached("devices")
        if cached is not None:
            return cached

        devices = {}
        from config.vault_client import get_device_credentials
        username, password = get_device_credentials()

        for device in self._get_all_devices():
            name = device.name

            # Get device type from custom field or map from device_type
            device_type = None
            if hasattr(device, "custom_fields") and device.custom_fields:
                device_type = device.custom_fields.get("netmiko_device_type")

            # Fallback: infer from device type slug
            if not device_type:
                type_slug = device.device_type.slug if device.device_type else ""
                type_slug_lower = type_slug.lower()

                # Cisco IOS-XE
                if "c8000v" in type_slug_lower or "cat9k" in type_slug_lower or "csr1000v" in type_slug_lower:
                    device_type = "cisco_xe"
                # Juniper Junos
                elif "vmx" in type_slug_lower or "junos" in type_slug_lower or "srx" in type_slug_lower or "qfx" in type_slug_lower:
                    device_type = "juniper_junos"
                # HPE Aruba CX
                elif "aruba-cx" in type_slug_lower or "aos-cx" in type_slug_lower or "arubaos-cx" in type_slug_lower:
                    device_type = "aruba_aoscx"
                # HPE ProCurve
                elif "procurve" in type_slug_lower or "aruba-switch" in type_slug_lower:
                    device_type = "hp_procurve"
                # HPE Comware
                elif "comware" in type_slug_lower or "h3c" in type_slug_lower or "flexfabric" in type_slug_lower:
                    device_type = "hp_comware"
                # Containerlab - SR Linux
                elif "srlinux" in type_slug_lower:
                    device_type = "containerlab_srlinux"
                # Containerlab - FRRouting
                elif "frr" in type_slug_lower:
                    device_type = "containerlab_frr"
                # Linux
                elif "alpine" in type_slug_lower or "linux" in type_slug_lower or "ubuntu" in type_slug_lower:
                    if device.site and "containerlab" in device.site.slug.lower():
                        device_type = "containerlab_linux"
                    else:
                        device_type = "linux"
                else:
                    device_type = "unknown"

            # Get management IP
            host = None
            if device.primary_ip4:
                host = str(device.primary_ip4.address).split("/")[0]

            # Build device entry
            device_entry = {
                "device_type": device_type,
                "host": host,
            }

            # Add credentials for non-containerlab devices
            if not device_type.startswith("containerlab_"):
                device_entry["username"] = username
                device_entry["password"] = password
            else:
                # Get container name from custom field
                container = None
                if hasattr(device, "custom_fields") and device.custom_fields:
                    container = device.custom_fields.get("container_name")
                if container:
                    device_entry["container"] = container

            devices[name] = device_entry

        self._set_cached("devices", devices)
        return devices

    def get_device_hosts(self) -> dict[str, str]:
        """Get device hosts mapping (name -> IP).

        Returns:
            Dict matching the format of config/devices.py DEVICE_HOSTS
        """
        cached = self._get_cached("device_hosts")
        if cached is not None:
            return cached

        hosts = {}
        for device in self._get_all_devices():
            if device.primary_ip4:
                ip = str(device.primary_ip4.address).split("/")[0]
                hosts[device.name] = ip

        self._set_cached("device_hosts", hosts)
        return hosts

    def get_device(self, name: str) -> dict | None:
        """Get single device by name.

        Args:
            name: Device name

        Returns:
            Device dict or None
        """
        devices = self.get_devices()
        return devices.get(name)

    def get_interfaces(self, device_name: str) -> list[dict]:
        """Get all interfaces for a device.

        Args:
            device_name: Device name

        Returns:
            List of interface dicts with name, type, enabled, ip_addresses
        """
        cache_key = f"interfaces_{device_name}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        interfaces = []
        device = self.api.dcim.devices.get(name=device_name)
        if not device:
            return []

        for intf in self.api.dcim.interfaces.filter(device_id=device.id):
            intf_data = {
                "name": intf.name,
                "type": intf.type.value if intf.type else None,
                "enabled": intf.enabled,
                "description": intf.description,
                "ip_addresses": [],
            }

            # Get IP addresses for this interface
            for ip in self.api.ipam.ip_addresses.filter(interface_id=intf.id):
                intf_data["ip_addresses"].append(str(ip.address))

            interfaces.append(intf_data)

        self._set_cached(cache_key, interfaces)
        return interfaces

    def get_ip_addresses(self, device_name: str = None) -> list[dict]:
        """Get IP addresses, optionally filtered by device.

        Args:
            device_name: Optional device name filter

        Returns:
            List of IP address dicts
        """
        cache_key = f"ip_addresses_{device_name or 'all'}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        ip_list = []
        if device_name:
            device = self.api.dcim.devices.get(name=device_name)
            if not device:
                return []
            ips = self.api.ipam.ip_addresses.filter(device_id=device.id)
        else:
            ips = self.api.ipam.ip_addresses.all()

        for ip in ips:
            ip_data = {
                "address": str(ip.address),
                "status": ip.status.value if ip.status else None,
                "description": ip.description,
                "interface": ip.assigned_object.name if ip.assigned_object else None,
                "device": ip.assigned_object.device.name
                if ip.assigned_object and hasattr(ip.assigned_object, "device")
                else None,
            }
            ip_list.append(ip_data)

        self._set_cached(cache_key, ip_list)
        return ip_list

    def get_cables(self) -> list[dict]:
        """Get all cable connections.

        Returns:
            List of cable dicts with endpoints
        """
        cached = self._get_cached("cables")
        if cached is not None:
            return cached

        cables = []
        for cable in self.api.dcim.cables.all():
            cable_data = {
                "id": cable.id,
                "a_terminations": [],
                "b_terminations": [],
                "status": cable.status.value if cable.status else None,
                "label": cable.label,
            }

            # Get A-side terminations
            if cable.a_terminations:
                for term in cable.a_terminations:
                    cable_data["a_terminations"].append(
                        {
                            "device": term.device.name if hasattr(term, "device") else None,
                            "interface": term.name if hasattr(term, "name") else str(term),
                        }
                    )

            # Get B-side terminations
            if cable.b_terminations:
                for term in cable.b_terminations:
                    cable_data["b_terminations"].append(
                        {
                            "device": term.device.name if hasattr(term, "device") else None,
                            "interface": term.name if hasattr(term, "name") else str(term),
                        }
                    )

            cables.append(cable_data)

        self._set_cached("cables", cables)
        return cables

    def get_prefixes(self) -> list[dict]:
        """Get all IP prefixes.

        Returns:
            List of prefix dicts
        """
        cached = self._get_cached("prefixes")
        if cached is not None:
            return cached

        prefixes = []
        for prefix in self.api.ipam.prefixes.all():
            prefix_data = {
                "prefix": str(prefix.prefix),
                "status": prefix.status.value if prefix.status else None,
                "description": prefix.description,
                "site": prefix.site.name if prefix.site else None,
                "vlan": prefix.vlan.vid if prefix.vlan else None,
                "role": prefix.role.name if prefix.role else None,
            }
            prefixes.append(prefix_data)

        self._set_cached("prefixes", prefixes)
        return prefixes

    def get_regions(self) -> list[dict]:
        """Get all regions.

        Returns:
            List of region dicts with id, name, slug
        """
        cached = self._get_cached("regions")
        if cached is not None:
            return cached

        regions = []
        for region in self.api.dcim.regions.all():
            region_data = {
                "id": region.slug,
                "name": region.name,
            }
            regions.append(region_data)

        self._set_cached("regions", regions)
        return regions

    def get_sites(self) -> list[dict]:
        """Get all sites with region info.

        Returns:
            List of site dicts with id, name, region
        """
        cached = self._get_cached("sites")
        if cached is not None:
            return cached

        sites = []
        for site in self.api.dcim.sites.all():
            site_data = {
                "id": site.slug,
                "name": site.name,
                "region": site.region.slug if site.region else None,
            }
            sites.append(site_data)

        self._set_cached("sites", sites)
        return sites

    def get_locations(self) -> list[dict]:
        """Get all locations (racks) with site info.

        Returns:
            List of location dicts with id, name, site
        """
        cached = self._get_cached("locations")
        if cached is not None:
            return cached

        locations = []
        for location in self.api.dcim.locations.all():
            location_data = {
                "id": location.slug,
                "name": location.name,
                "site": location.site.slug if location.site else None,
            }
            locations.append(location_data)

        self._set_cached("locations", locations)
        return locations

    def get_device_locations(self) -> dict[str, dict]:
        """Get device to location (rack) mapping.

        Returns:
            Dict of device_name -> {"rack": location_slug}
        """
        cached = self._get_cached("device_locations")
        if cached is not None:
            return cached

        device_locations = {}
        for device in self._get_all_devices():
            if device.location:
                device_locations[device.name] = {
                    "rack": device.location.slug,
                }

        self._set_cached("device_locations", device_locations)
        return device_locations

    def get_hierarchy_data(self) -> dict:
        """Get complete hierarchy data for integration.

        Returns:
            Dict with regions, sites, locations (racks), and device_locations
        """
        return {
            "regions": self.get_regions(),
            "sites": self.get_sites(),
            "racks": self.get_locations(),
            "device_locations": self.get_device_locations(),
        }

    def get_loopbacks(self, role: str = None) -> dict[str, str]:
        """Get loopback IPs for devices.

        Args:
            role: Optional device role filter ('router', 'switch')

        Returns:
            Dict of device_name -> loopback_ip
        """
        loopbacks = {}

        # Filter devices by role if specified, and always by tenant if configured
        filter_kwargs = {}
        if self.tenant:
            filter_kwargs["tenant"] = self.tenant
        if role:
            filter_kwargs["role"] = role

        if filter_kwargs:
            devices = self.api.dcim.devices.filter(**filter_kwargs)
        else:
            devices = self.api.dcim.devices.all()

        for device in devices:
            # Find Loopback0 interface
            loopback_intf = self.api.dcim.interfaces.get(
                device_id=device.id, name="Loopback0"
            )
            if loopback_intf:
                ips = self.api.ipam.ip_addresses.filter(interface_id=loopback_intf.id)
                for ip in ips:
                    loopbacks[device.name] = str(ip.address).split("/")[0]
                    break

        return loopbacks

    def test_connection(self) -> bool:
        """Test NetBox API connectivity.

        Returns:
            True if connection successful
        """
        try:
            self.api.status()
            self._circuit_breaker.record_success()
            return True
        except Exception as e:
            self._circuit_breaker.record_failure()
            return False

    def get_circuit_status(self) -> dict:
        """Get current circuit breaker status.

        Returns:
            Dict with state, failure_count, is_allowing_requests
        """
        status = self._circuit_breaker.get_status()
        return {
            "state": status.state.value,
            "failure_count": status.failure_count,
            "is_allowing_requests": status.is_allowing_requests,
            "service": status.service_name,
        }

    def reset_circuit(self):
        """Manually reset the circuit breaker."""
        self._circuit_breaker.reset()
        logger.info("NetBox circuit breaker manually reset")

    def get_device_types(self) -> list[dict]:
        """Get available device types for dropdown.

        Returns:
            List of device type dicts with id, model, manufacturer
        """
        cached = self._get_cached("device_types")
        if cached is not None:
            return cached

        device_types = []
        for dt in self.api.dcim.device_types.all():
            device_types.append({
                "id": dt.id,
                "model": dt.model,
                "slug": dt.slug,
                "manufacturer": dt.manufacturer.name if dt.manufacturer else None,
            })

        self._set_cached("device_types", device_types)
        return device_types

    def get_device_roles(self) -> list[dict]:
        """Get available device roles for dropdown.

        Returns:
            List of device role dicts with id, name, slug
        """
        cached = self._get_cached("device_roles")
        if cached is not None:
            return cached

        roles = []
        for role in self.api.dcim.device_roles.all():
            roles.append({
                "id": role.id,
                "name": role.name,
                "slug": role.slug,
            })

        self._set_cached("device_roles", roles)
        return roles

    def create_device(
        self,
        name: str,
        device_type_id: int,
        role_id: int,
        site_id: int,
        location_id: int | None = None,
        primary_ip: str | None = None,
        netmiko_device_type: str | None = None,
        container_name: str | None = None,
    ) -> dict:
        """Create a new device in NetBox.

        Args:
            name: Device hostname
            device_type_id: NetBox device type ID
            role_id: NetBox device role ID
            site_id: NetBox site ID
            location_id: Optional NetBox location (rack) ID
            primary_ip: Optional management IP address (e.g., "10.255.255.50/24")
            netmiko_device_type: Optional Netmiko device type for automation
            container_name: Optional container name for containerlab devices

        Returns:
            Created device data dict

        Raises:
            Exception: If device creation fails
        """
        # Build device data
        device_data = {
            "name": name,
            "device_type": device_type_id,
            "role": role_id,
            "site": site_id,
            "status": "active",
        }

        if location_id:
            device_data["location"] = location_id

        # Add custom fields for automation
        custom_fields = {}
        if netmiko_device_type:
            custom_fields["netmiko_device_type"] = netmiko_device_type
        if container_name:
            custom_fields["container_name"] = container_name
        if custom_fields:
            device_data["custom_fields"] = custom_fields

        # Create the device
        device = self.api.dcim.devices.create(**device_data)

        # If IP provided, create interface and assign IP
        if primary_ip and device:
            # Create management interface
            mgmt_intf = self.api.dcim.interfaces.create(
                device=device.id,
                name="GigabitEthernet4",
                type="1000base-t",
                description="Management",
            )

            # Create IP address and assign to interface
            ip = self.api.ipam.ip_addresses.create(
                address=primary_ip,
                assigned_object_type="dcim.interface",
                assigned_object_id=mgmt_intf.id,
                status="active",
            )

            # Set as primary IP
            device.primary_ip4 = ip.id
            device.save()

        # Clear cache so new device shows up
        self.refresh_cache()

        return {
            "id": device.id,
            "name": device.name,
            "status": "created",
        }

    def get_sites_for_dropdown(self) -> list[dict]:
        """Get sites with IDs for dropdown selection.

        Returns:
            List of site dicts with id (int), name, slug
        """
        sites = []
        for site in self.api.dcim.sites.all():
            sites.append({
                "id": site.id,
                "name": site.name,
                "slug": site.slug,
            })
        return sites

    def get_locations_for_dropdown(self, site_id: int | None = None) -> list[dict]:
        """Get locations (racks) with IDs for dropdown selection.

        Args:
            site_id: Optional site ID to filter by

        Returns:
            List of location dicts with id (int), name, slug, site_id
        """
        locations = []
        if site_id:
            locs = self.api.dcim.locations.filter(site_id=site_id)
        else:
            locs = self.api.dcim.locations.all()

        for loc in locs:
            locations.append({
                "id": loc.id,
                "name": loc.name,
                "slug": loc.slug,
                "site_id": loc.site.id if loc.site else None,
            })
        return locations

    def get_next_available_ip(
        self,
        prefix: str = "10.255.255.0/24",
        correlation_id: str = "",
    ) -> str:
        """Find the next available IP address in a prefix.

        Queries NetBox IPAM for used IPs in the prefix and returns
        the next available one.

        Args:
            prefix: CIDR notation prefix (default: management network)
            correlation_id: Optional ID for log correlation

        Returns:
            Next available IP with CIDR (e.g., "10.255.255.48/24")

        Raises:
            ValueError: If prefix not found, exhausted, or NetBox unavailable
        """
        import ipaddress
        import logging

        logger = logging.getLogger(__name__)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Looking for next available IP in {prefix}")

        # Parse the prefix to get network details
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid prefix format: {prefix}") from e

        # Get the prefix from NetBox IPAM
        nb_prefix = self.api.ipam.prefixes.get(prefix=prefix)
        if not nb_prefix:
            raise ValueError(f"Prefix {prefix} not found in NetBox IPAM")

        # Get all IP addresses in this prefix
        used_ips = set()
        for ip in self.api.ipam.ip_addresses.filter(parent=prefix):
            # Extract just the IP part (without CIDR)
            ip_str = str(ip.address).split("/")[0]
            used_ips.add(ip_str)

        logger.debug(f"{log_prefix}Found {len(used_ips)} used IPs in {prefix}")

        # Find the first available IP
        # Skip network address (.0), gateway (.1), and broadcast (.255 for /24)
        prefix_len = network.prefixlen
        for host in network.hosts():
            host_str = str(host)

            # Skip .1 (typically gateway)
            if host_str.endswith(".1"):
                continue

            # Skip if already in use
            if host_str in used_ips:
                continue

            # Found an available IP
            next_ip = f"{host_str}/{prefix_len}"
            logger.info(f"{log_prefix}Found available IP: {next_ip}")
            return next_ip

        # No available IPs
        raise ValueError(f"Prefix {prefix} is exhausted - no available IPs")

    def allocate_ip(
        self,
        prefix: str = "10.255.255.0/24",
        device_name: str | None = None,
        interface_name: str = "GigabitEthernet4",
        description: str | None = None,
        correlation_id: str = "",
    ) -> dict:
        """Allocate the next available IP from a prefix.

        Gets the next available IP and creates it in NetBox.
        Optionally assigns it to a device interface.

        Args:
            prefix: CIDR notation prefix (default: management network)
            device_name: Optional device to assign IP to
            interface_name: Interface name if assigning to device
            description: Optional IP description
            correlation_id: Optional ID for log correlation

        Returns:
            Dict with allocated IP info:
                - address: The allocated IP with CIDR (e.g., "10.255.255.48/24")
                - id: NetBox IP address ID
                - assigned_to: Device/interface if assigned

        Raises:
            ValueError: If prefix exhausted or device/interface not found
        """
        import logging

        logger = logging.getLogger(__name__)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        # Get next available IP
        next_ip = self.get_next_available_ip(prefix, correlation_id)
        logger.info(f"{log_prefix}Allocating IP: {next_ip}")

        # Build IP creation data
        ip_data = {
            "address": next_ip,
            "status": "active",
        }

        if description:
            ip_data["description"] = description

        # If device specified, find the interface
        assigned_to = None
        if device_name:
            device = self.api.dcim.devices.get(name=device_name)
            if not device:
                raise ValueError(f"Device not found: {device_name}")

            intf = self.api.dcim.interfaces.get(
                device_id=device.id,
                name=interface_name,
            )
            if not intf:
                # Create the interface if it doesn't exist
                logger.info(f"{log_prefix}Creating interface {interface_name} on {device_name}")
                intf = self.api.dcim.interfaces.create(
                    device=device.id,
                    name=interface_name,
                    type="1000base-t",
                    description="Management",
                )

            ip_data["assigned_object_type"] = "dcim.interface"
            ip_data["assigned_object_id"] = intf.id
            assigned_to = f"{device_name}:{interface_name}"

        # Create the IP in NetBox
        created_ip = self.api.ipam.ip_addresses.create(**ip_data)

        # Set as primary IP if assigned to device
        if device_name and created_ip:
            device = self.api.dcim.devices.get(name=device_name)
            if device:
                device.primary_ip4 = created_ip.id
                device.save()
                logger.info(f"{log_prefix}Set {next_ip} as primary IP for {device_name}")

        # Clear cache
        self.refresh_cache()

        return {
            "address": next_ip,
            "id": created_ip.id,
            "assigned_to": assigned_to,
        }

    def release_ip(self, ip_address: str, correlation_id: str = "") -> bool:
        """Release an allocated IP address back to the pool.

        Args:
            ip_address: IP address to release (with or without CIDR)
            correlation_id: Optional ID for log correlation

        Returns:
            True if IP was deleted, False if not found
        """
        import logging

        logger = logging.getLogger(__name__)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        # Handle both "10.255.255.48" and "10.255.255.48/24" formats
        ip_str = ip_address.split("/")[0]

        logger.info(f"{log_prefix}Releasing IP: {ip_str}")

        # Find the IP in NetBox
        # Try with and without CIDR suffix
        ip_obj = None
        for ip in self.api.ipam.ip_addresses.filter(address=ip_str):
            ip_obj = ip
            break

        if not ip_obj:
            logger.warning(f"{log_prefix}IP not found in NetBox: {ip_str}")
            return False

        # Delete the IP
        ip_obj.delete()
        logger.info(f"{log_prefix}Deleted IP: {ip_str}")

        # Clear cache
        self.refresh_cache()

        return True

    def delete_device(self, device_id: int, correlation_id: str = "") -> bool:
        """Delete a device from NetBox.

        Args:
            device_id: NetBox device ID
            correlation_id: Optional ID for log correlation

        Returns:
            True if device was deleted, False if not found
        """
        import logging

        logger = logging.getLogger(__name__)
        log_prefix = f"[{correlation_id}] " if correlation_id else ""

        logger.info(f"{log_prefix}Deleting device ID: {device_id}")

        try:
            device = self.api.dcim.devices.get(device_id)
            if not device:
                logger.warning(f"{log_prefix}Device not found: {device_id}")
                return False

            device.delete()
            logger.info(f"{log_prefix}Deleted device: {device_id}")

            # Clear cache
            self.refresh_cache()

            return True

        except Exception as e:
            logger.error(f"{log_prefix}Failed to delete device {device_id}: {e}")
            raise


# Singleton instance
_client: NetBoxClient | None = None


def get_client() -> NetBoxClient:
    """Get or create NetBox client singleton.

    Returns:
        NetBoxClient instance
    """
    global _client
    if _client is None:
        _client = NetBoxClient()
    return _client


def is_netbox_available() -> bool:
    """Check if NetBox is available and configured.

    Returns:
        True if NetBox is reachable
    """
    from config.vault_client import get_netbox_token
    if not get_netbox_token():
        return False
    try:
        return get_client().test_connection()
    except Exception:
        return False
