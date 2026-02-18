#!/usr/bin/env python3
"""
Populate NetBox with network lab data.

Run this script once to migrate from static config to NetBox.
Idempotent - can be re-run safely.

Usage:
    python scripts/populate_netbox.py [--refresh]

Options:
    --refresh   Clear existing data before populating
"""

import argparse
import os
import sys

import pynetbox
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.netbox_data import (
    CABLES,
    DEVICE_ROLES,
    DEVICE_TYPES,
    DEVICES,
    LOCATIONS,
    MANUFACTURERS,
    PREFIXES,
    REGIONS,
    SITES,
)

load_dotenv()

# NetBox connection
NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000")


def get_api() -> pynetbox.api:
    """Get authenticated pynetbox API client."""
    from config.vault_client import get_netbox_token
    token = get_netbox_token()
    if not token:
        print("Error: NETBOX_API_TOKEN not set in environment")
        sys.exit(1)

    api = pynetbox.api(NETBOX_URL, token=token)
    api.http_session.verify = False  # For local dev
    return api


def create_manufacturers(api: pynetbox.api) -> dict:
    """Create manufacturers, return name->id mapping."""
    print("\n=== Creating Manufacturers ===")
    mapping = {}

    for mfr in MANUFACTURERS:
        existing = api.dcim.manufacturers.get(slug=mfr["slug"])
        if existing:
            print(f"  [exists] {mfr['name']}")
            mapping[mfr["slug"]] = existing.id
        else:
            created = api.dcim.manufacturers.create(mfr)
            print(f"  [created] {mfr['name']}")
            mapping[mfr["slug"]] = created.id

    return mapping


def create_device_types(api: pynetbox.api, mfr_mapping: dict) -> dict:
    """Create device types, return slug->id mapping."""
    print("\n=== Creating Device Types ===")
    mapping = {}

    for dt in DEVICE_TYPES:
        existing = api.dcim.device_types.get(slug=dt["slug"])
        if existing:
            print(f"  [exists] {dt['model']}")
            mapping[dt["slug"]] = existing.id
        else:
            dt_data = {
                "manufacturer": mfr_mapping[dt["manufacturer"]],
                "model": dt["model"],
                "slug": dt["slug"],
                "u_height": dt.get("u_height", 1),
                "is_full_depth": dt.get("is_full_depth", False),
            }
            created = api.dcim.device_types.create(dt_data)
            print(f"  [created] {dt['model']}")
            mapping[dt["slug"]] = created.id

    return mapping


def create_device_roles(api: pynetbox.api) -> dict:
    """Create device roles, return slug->id mapping."""
    print("\n=== Creating Device Roles ===")
    mapping = {}

    for role in DEVICE_ROLES:
        existing = api.dcim.device_roles.get(slug=role["slug"])
        if existing:
            print(f"  [exists] {role['name']}")
            mapping[role["slug"]] = existing.id
        else:
            created = api.dcim.device_roles.create(role)
            print(f"  [created] {role['name']}")
            mapping[role["slug"]] = created.id

    return mapping


def create_regions(api: pynetbox.api) -> dict:
    """Create regions, return slug->id mapping."""
    print("\n=== Creating Regions ===")
    mapping = {}

    for region in REGIONS:
        existing = api.dcim.regions.get(slug=region["slug"])
        if existing:
            print(f"  [exists] {region['name']}")
            mapping[region["slug"]] = existing.id
        else:
            created = api.dcim.regions.create(region)
            print(f"  [created] {region['name']}")
            mapping[region["slug"]] = created.id

    return mapping


def create_sites(api: pynetbox.api, region_mapping: dict) -> dict:
    """Create sites, return slug->id mapping."""
    print("\n=== Creating Sites ===")
    mapping = {}

    for site in SITES:
        existing = api.dcim.sites.get(slug=site["slug"])
        if existing:
            print(f"  [exists] {site['name']}")
            mapping[site["slug"]] = existing.id
            # Update region if needed
            if site.get("region") and existing.region is None:
                existing.region = region_mapping.get(site["region"])
                existing.save()
                print(f"    [updated] Added region {site['region']}")
        else:
            site_data = dict(site)
            if site_data.get("region"):
                site_data["region"] = region_mapping.get(site_data["region"])
            created = api.dcim.sites.create(site_data)
            print(f"  [created] {site['name']}")
            mapping[site["slug"]] = created.id

    return mapping


def create_locations(api: pynetbox.api, site_mapping: dict) -> dict:
    """Create locations (racks), return slug->id mapping."""
    print("\n=== Creating Locations ===")
    mapping = {}

    for location in LOCATIONS:
        existing = api.dcim.locations.get(slug=location["slug"])
        if existing:
            print(f"  [exists] {location['name']}")
            mapping[location["slug"]] = existing.id
        else:
            location_data = {
                "name": location["name"],
                "slug": location["slug"],
                "site": site_mapping.get(location["site"]),
                "description": location.get("description", ""),
            }
            created = api.dcim.locations.create(location_data)
            print(f"  [created] {location['name']}")
            mapping[location["slug"]] = created.id

    return mapping


def create_prefixes(api: pynetbox.api) -> None:
    """Create IP prefixes."""
    print("\n=== Creating Prefixes ===")

    for prefix in PREFIXES:
        existing = api.ipam.prefixes.get(prefix=prefix["prefix"])
        if existing:
            print(f"  [exists] {prefix['prefix']}")
        else:
            api.ipam.prefixes.create(prefix)
            print(f"  [created] {prefix['prefix']}")


def create_custom_fields(api: pynetbox.api) -> None:
    """Create custom fields for device metadata."""
    print("\n=== Creating Custom Fields ===")

    custom_fields = [
        {
            "name": "netmiko_device_type",
            "label": "Netmiko Device Type",
            "type": "text",
            "description": "Device type for Netmiko/Scrapli connections",
            "object_types": ["dcim.device"],
        },
        {
            "name": "netconf_enabled",
            "label": "NETCONF Enabled",
            "type": "boolean",
            "description": "Whether NETCONF is enabled on this device",
            "object_types": ["dcim.device"],
        },
        {
            "name": "container_name",
            "label": "Container Name",
            "type": "text",
            "description": "Docker container name for containerlab devices",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_asn",
            "label": "BGP ASN",
            "type": "integer",
            "description": "BGP Autonomous System Number",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_peers",
            "label": "BGP Peers",
            "type": "json",
            "description": "BGP peer list [{neighbor, remote_as, ebgp_multihop?, update_source?}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_networks",
            "label": "BGP Networks",
            "type": "json",
            "description": "BGP network statements [{prefix}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_enabled",
            "label": "OSPF Enabled",
            "type": "boolean",
            "description": "Whether OSPF is enabled on this device",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_interfaces",
            "label": "OSPF Interfaces",
            "type": "json",
            "description": "Per-interface OSPF settings [{name, area?, mtu_ignore?, network_type?, priority?, passive?}] and network statements [{network, area}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_redistribute",
            "label": "OSPF Redistribute",
            "type": "json",
            "description": "OSPF redistribution rules [{type, route_map?}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "static_routes",
            "label": "Static Routes",
            "type": "json",
            "description": "Static routes [{prefix, next_hop}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "frr_extra_config",
            "label": "FRR Extra Config",
            "type": "text",
            "description": "Extra FRR config lines (prefix-lists, route-maps, etc.)",
            "object_types": ["dcim.device"],
        },
        # IOS-XE specific fields
        {
            "name": "ospf_process_id",
            "label": "OSPF Process ID",
            "type": "integer",
            "description": "OSPF process ID (e.g. 1)",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_passive_interfaces",
            "label": "OSPF Passive Interfaces",
            "type": "json",
            "description": "List of passive interfaces [\"Loopback0\", \"GigabitEthernet3\"]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_peer_groups",
            "label": "BGP Peer Groups",
            "type": "json",
            "description": "BGP peer groups [{name, remote_as, update_source?}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_address_families",
            "label": "BGP Address Families",
            "type": "json",
            "description": "Per-AF BGP config [{afi, neighbors, networks, rr_client_groups?}]",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ntp_config",
            "label": "NTP Config",
            "type": "json",
            "description": "NTP settings {servers, source?, master?, authenticate?}",
            "object_types": ["dcim.device"],
        },
        {
            "name": "iosxe_interface_extra",
            "label": "IOS-XE Interface Extra Lines",
            "type": "json",
            "description": "Per-interface non-standard lines {\"Gi1\": [\"ip pim sparse-mode\"]}",
            "object_types": ["dcim.device"],
        },
        {
            "name": "iosxe_preamble",
            "label": "IOS-XE Preamble",
            "type": "text",
            "description": "Verbatim config from 'version' through crypto/QoS (before first interface)",
            "object_types": ["dcim.device"],
        },
        {
            "name": "iosxe_postamble",
            "label": "IOS-XE Postamble",
            "type": "text",
            "description": "Verbatim config after routing/NTP (ip http, ACLs, control-plane, banner, line, etc.)",
            "object_types": ["dcim.device"],
        },
        {
            "name": "iosxe_routing_extra",
            "label": "IOS-XE Routing Extra",
            "type": "text",
            "description": "Verbatim non-OSPF/BGP routing blocks (router eigrp, router ospfv3, etc.)",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_bfd",
            "label": "OSPF BFD All Interfaces",
            "type": "boolean",
            "description": "Whether 'bfd all-interfaces' is enabled under router ospf",
            "object_types": ["dcim.device"],
        },
        {
            "name": "ospf_areas",
            "label": "OSPF Area Types",
            "type": "json",
            "description": "OSPF area type overrides, e.g. {\"1\": \"stub\"}",
            "object_types": ["dcim.device"],
        },
        {
            "name": "bgp_no_default_ipv4",
            "label": "BGP No Default IPv4 Unicast",
            "type": "boolean",
            "description": "Whether 'no bgp default ipv4-unicast' is configured",
            "object_types": ["dcim.device"],
        },
    ]

    for cf in custom_fields:
        existing = api.extras.custom_fields.get(name=cf["name"])
        if existing:
            print(f"  [exists] {cf['name']}")
        else:
            api.extras.custom_fields.create(cf)
            print(f"  [created] {cf['name']}")


def create_devices(
    api: pynetbox.api,
    dt_mapping: dict,
    role_mapping: dict,
    site_mapping: dict,
    location_mapping: dict,
) -> dict:
    """Create devices, return name->id mapping."""
    print("\n=== Creating Devices ===")
    mapping = {}

    for device in DEVICES:
        existing = api.dcim.devices.get(name=device["name"])
        if existing:
            print(f"  [exists] {device['name']}")
            mapping[device["name"]] = existing.id

            # Check if site needs updating
            expected_site_id = site_mapping.get(device["site"])
            current_site_id = existing.site.id if existing.site else None
            site_changed = expected_site_id and current_site_id != expected_site_id

            # Check if location needs updating
            expected_location_id = location_mapping.get(device.get("location"))
            current_location_id = existing.location.id if existing.location else None
            location_changed = device.get("location") and current_location_id != expected_location_id

            if site_changed or location_changed:
                if site_changed:
                    existing.site = expected_site_id
                    print(f"    [updated] Changed site to {device['site']}")
                if location_changed:
                    existing.location = expected_location_id
                    print(f"    [updated] Changed location to {device['location']}")
                existing.save()

            # Update custom fields if they differ
            expected_cf = device.get("custom_fields", {})
            if expected_cf:
                current_cf = existing.custom_fields or {}
                cf_changed = False
                for key, value in expected_cf.items():
                    if current_cf.get(key) != value:
                        cf_changed = True
                        break
                if cf_changed:
                    existing.custom_fields = expected_cf
                    existing.save()
                    print(f"    [updated] Custom fields")
        else:
            device_data = {
                "name": device["name"],
                "device_type": dt_mapping[device["device_type"]],
                "role": role_mapping[device["role"]],
                "site": site_mapping[device["site"]],
                "status": device.get("status", "active"),
                "custom_fields": device.get("custom_fields", {}),
            }
            if device.get("location"):
                device_data["location"] = location_mapping.get(device["location"])
            created = api.dcim.devices.create(device_data)
            print(f"  [created] {device['name']}")
            mapping[device["name"]] = created.id

    return mapping


def create_interfaces(api: pynetbox.api, device_mapping: dict) -> dict:
    """Create interfaces for all devices, return (device,interface)->id mapping."""
    print("\n=== Creating Interfaces ===")
    mapping = {}

    # Interface type mapping
    type_map = {
        "1000base-t": "1000base-t",
        "virtual": "virtual",
        "100base-tx": "100base-tx",
    }

    for device in DEVICES:
        device_id = device_mapping[device["name"]]
        print(f"  Device: {device['name']}")

        for intf in device.get("interfaces", []):
            existing = api.dcim.interfaces.get(
                device_id=device_id, name=intf["name"]
            )
            if existing:
                changed = False
                # Update description if changed
                expected_desc = intf.get("description", "") or ""
                current_desc = existing.description or ""
                if current_desc != expected_desc:
                    existing.description = expected_desc
                    changed = True
                    print(f"    [updated desc] {intf['name']}: {expected_desc!r}")
                # Update enabled if changed
                expected_enabled = intf.get("enabled", True)
                if existing.enabled != expected_enabled:
                    existing.enabled = expected_enabled
                    changed = True
                    print(f"    [updated enabled] {intf['name']}: {expected_enabled}")
                if changed:
                    existing.save()
                elif not changed:
                    print(f"    [exists] {intf['name']}")
                mapping[(device["name"], intf["name"])] = existing.id
            else:
                intf_data = {
                    "device": device_id,
                    "name": intf["name"],
                    "type": type_map.get(intf.get("type", "virtual"), "virtual"),
                    "enabled": intf.get("enabled", True),
                    "description": intf.get("description", ""),
                }
                created = api.dcim.interfaces.create(intf_data)
                print(f"    [created] {intf['name']}")
                mapping[(device["name"], intf["name"])] = created.id

    return mapping


def assign_ip_addresses(api: pynetbox.api, intf_mapping: dict, device_mapping: dict) -> None:
    """Assign IP addresses to interfaces."""
    print("\n=== Assigning IP Addresses ===")

    for device in DEVICES:
        device_id = device_mapping[device["name"]]
        print(f"  Device: {device['name']}")
        primary_ip = None

        for ip_info in device.get("ip_addresses", []):
            intf_id = intf_mapping.get((device["name"], ip_info["interface"]))
            if not intf_id:
                print(f"    [skip] {ip_info['address']} - interface not found")
                continue

            # Search by exact CIDR first, then by host part (handles mask changes)
            existing = api.ipam.ip_addresses.get(address=ip_info["address"])
            if not existing:
                ip_host = ip_info["address"].split("/")[0]
                for candidate in api.ipam.ip_addresses.filter(address=ip_host):
                    existing = candidate
                    break

            if existing:
                needs_save = False

                # Update prefix length if changed (e.g. /24 -> /30)
                if str(existing.address) != ip_info["address"]:
                    existing.address = ip_info["address"]
                    needs_save = True
                    print(f"    [updated mask] {ip_info['address']}")

                # Update assignment if needed
                if existing.assigned_object_id != intf_id:
                    # Clear primary IP on old device if this IP is set as primary
                    if existing.assigned_object:
                        try:
                            old_intf = api.dcim.interfaces.get(existing.assigned_object_id)
                            if old_intf and old_intf.device:
                                old_device = api.dcim.devices.get(old_intf.device.id)
                                if old_device and old_device.primary_ip4 and old_device.primary_ip4.id == existing.id:
                                    old_device.primary_ip4 = None
                                    old_device.save()
                                    print(f"    [cleared primary on {old_device.name}]")
                        except Exception:
                            pass  # Ignore errors clearing old primary
                    existing.assigned_object_type = "dcim.interface"
                    existing.assigned_object_id = intf_id
                    needs_save = True
                    print(f"    [updated] {ip_info['address']}")
                elif not needs_save:
                    print(f"    [exists] {ip_info['address']}")

                if needs_save:
                    existing.save()
                ip_id = existing.id
            else:
                ip_data = {
                    "address": ip_info["address"],
                    "status": ip_info.get("status", "active"),
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": intf_id,
                }
                created = api.ipam.ip_addresses.create(ip_data)
                print(f"    [created] {ip_info['address']}")
                ip_id = created.id

            # Track primary IP
            if ip_info.get("primary"):
                primary_ip = ip_id

        # Set primary IP on device
        if primary_ip:
            device_obj = api.dcim.devices.get(device_id)
            if device_obj.primary_ip4 is None or device_obj.primary_ip4.id != primary_ip:
                device_obj.primary_ip4 = primary_ip
                device_obj.save()
                print(f"    [primary] Set primary IP")


def create_cables(api: pynetbox.api, intf_mapping: dict) -> None:
    """Create cable connections between interfaces."""
    print("\n=== Creating Cables ===")

    for cable in CABLES:
        a_intf_id = intf_mapping.get((cable["a_device"], cable["a_interface"]))
        b_intf_id = intf_mapping.get((cable["b_device"], cable["b_interface"]))

        if not a_intf_id or not b_intf_id:
            print(f"  [skip] {cable['a_device']}:{cable['a_interface']} <-> {cable['b_device']}:{cable['b_interface']} - interface not found")
            continue

        # Check if cable already exists
        a_intf = api.dcim.interfaces.get(a_intf_id)
        if a_intf.cable:
            print(f"  [exists] {cable['a_device']}:{cable['a_interface']} <-> {cable['b_device']}:{cable['b_interface']}")
            continue

        cable_data = {
            "a_terminations": [
                {"object_type": "dcim.interface", "object_id": a_intf_id}
            ],
            "b_terminations": [
                {"object_type": "dcim.interface", "object_id": b_intf_id}
            ],
            "status": cable.get("status", "connected"),
        }

        try:
            api.dcim.cables.create(cable_data)
            print(f"  [created] {cable['a_device']}:{cable['a_interface']} <-> {cable['b_device']}:{cable['b_interface']}")
        except Exception as e:
            print(f"  [error] {cable['a_device']}:{cable['a_interface']} <-> {cable['b_device']}:{cable['b_interface']}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Populate NetBox with network lab data")
    parser.add_argument("--refresh", action="store_true", help="Clear existing data before populating")
    args = parser.parse_args()

    print(f"Connecting to NetBox at {NETBOX_URL}...")
    api = get_api()

    # Test connection
    try:
        status = api.status()
        print(f"Connected to NetBox {status.get('netbox-version', 'unknown')}")
    except Exception as e:
        print(f"Error connecting to NetBox: {e}")
        sys.exit(1)

    if args.refresh:
        print("\n!!! REFRESH MODE - This will NOT delete existing data, only update it !!!")
        # Note: We don't actually delete - just re-run creates which are idempotent

    # Create objects in order (respecting dependencies)
    create_custom_fields(api)
    mfr_mapping = create_manufacturers(api)
    dt_mapping = create_device_types(api, mfr_mapping)
    role_mapping = create_device_roles(api)
    region_mapping = create_regions(api)
    site_mapping = create_sites(api, region_mapping)
    location_mapping = create_locations(api, site_mapping)
    create_prefixes(api)
    device_mapping = create_devices(api, dt_mapping, role_mapping, site_mapping, location_mapping)
    intf_mapping = create_interfaces(api, device_mapping)
    assign_ip_addresses(api, intf_mapping, device_mapping)
    create_cables(api, intf_mapping)

    print("\n=== Population Complete ===")
    print(f"  Manufacturers: {len(mfr_mapping)}")
    print(f"  Device Types: {len(dt_mapping)}")
    print(f"  Device Roles: {len(role_mapping)}")
    print(f"  Regions: {len(region_mapping)}")
    print(f"  Sites: {len(site_mapping)}")
    print(f"  Locations: {len(location_mapping)}")
    print(f"  Devices: {len(device_mapping)}")
    print(f"  Interfaces: {len(intf_mapping)}")
    print(f"\nNetBox UI: {NETBOX_URL}")


if __name__ == "__main__":
    main()
