"""
NetBox IPAM/DCIM MCP tools.

Exposes NetBox as a source-of-truth for device inventory, IP address
management, cabling, and site hierarchy via MCP:

Read:
- netbox_status: Health, circuit breaker state, version, cache info
- netbox_get_devices: Device inventory with optional role/site filters
- netbox_get_interfaces: Interfaces + IPs for a single device
- netbox_get_prefixes: IP prefix inventory with optional status filter
- netbox_get_ip_addresses: IP address inventory with device/prefix filters
- netbox_get_cables: Cable connections with optional device filter
- netbox_get_hierarchy: Region → site → location → device tree

IPAM:
- netbox_suggest_ip: Preview next available IP (read-only)
- netbox_allocate_ip: Allocate IP and optionally assign to device
- netbox_release_ip: Release IP (refuses if assigned unless force=True)

Cache:
- netbox_refresh_cache: Clear cached data (repopulates on next tool call)
"""

import json
import logging
import time

logger = logging.getLogger(__name__)


# =============================================================================
# Internal Helpers
# =============================================================================

def _netbox_unavailable_error() -> str:
    """Standard error response when NetBox is not reachable."""
    from config.netbox_client import get_client, is_netbox_available

    result = {"error": "NetBox is not available. Check connection and API token."}
    try:
        client = get_client()
        cb_status = client.get_circuit_status()
        # Ensure circuit breaker status is JSON-serializable
        if isinstance(cb_status, dict):
            result["circuit_breaker"] = cb_status
    except Exception:
        pass
    return json.dumps(result, indent=2)


def _check_available() -> bool:
    """Return True if NetBox is available."""
    from config.netbox_client import is_netbox_available
    return is_netbox_available()


def _normalize_slug(value: str) -> str:
    """Normalize a display name or slug to slug format.

    Lowercases, replaces spaces with hyphens, strips whitespace.
    """
    return value.strip().lower().replace(" ", "-")


def _resolve_filter(api_app, slug_value: str):
    """Try to find an object by slug, fall back to case-insensitive name match.

    Args:
        api_app: pynetbox endpoint (e.g., api.dcim.device_roles)
        slug_value: User-provided name or slug

    Returns:
        Resolved slug string or None
    """
    normalized = _normalize_slug(slug_value)
    # Try slug directly
    obj = api_app.get(slug=normalized)
    if obj:
        return obj.slug

    # Fall back: search by name (case-insensitive via filter)
    results = list(api_app.filter(name=slug_value))
    if len(results) == 1:
        return results[0].slug
    return None


# =============================================================================
# Tool Functions
# =============================================================================

def netbox_status() -> str:
    """
    Check NetBox availability, version, circuit breaker state, and cache status.

    Returns health information useful for diagnosing connectivity issues
    and understanding the current data source (NetBox vs static fallback).

    Returns:
        JSON with availability, version, circuit breaker, cache info, device count
    """
    from config.netbox_client import get_client, NETBOX_URL, NETBOX_API_TOKEN

    result = {
        "available": False,
        "url": NETBOX_URL,
        "version": None,
        "circuit_breaker": None,
        "cache": {"entries": 0, "oldest_seconds": None},
        "data_source": "static",
        "device_count": 0,
        "last_success_ts": None,
    }

    if not NETBOX_API_TOKEN:
        result["error"] = "NETBOX_API_TOKEN not configured"
        return json.dumps(result, indent=2)

    try:
        client = get_client()
        result["circuit_breaker"] = client.get_circuit_status()

        # Cache info
        cache_entries = len(client._cache)
        oldest = None
        if client._cache_timestamps:
            oldest_ts = min(client._cache_timestamps.values())
            oldest = round(time.time() - oldest_ts, 1)
        result["cache"] = {"entries": cache_entries, "oldest_seconds": oldest}

        # Test connection and get version
        try:
            status = client.api.status()
            result["available"] = True
            result["version"] = status.get("netbox-version", None) if isinstance(status, dict) else None
            result["data_source"] = "netbox"
            result["last_success_ts"] = time.time()

            # Device count
            devices = client.get_devices()
            result["device_count"] = len(devices)
        except Exception as e:
            result["error"] = f"NetBox API error: {e}"

    except Exception as e:
        result["error"] = str(e)

    return json.dumps(result, indent=2)


def netbox_get_devices(role: str = "", site: str = "") -> str:
    """
    List devices from NetBox inventory with optional filters.

    Returns device name, role, site, location, type, primary IP, and status.
    Accepts display names or slugs for role and site filters.

    Args:
        role: Filter by device role (name or slug, e.g. "router" or "Router").
              Empty string returns all roles.
        site: Filter by site (name or slug, e.g. "eve-ng-lab" or "EVE-NG Lab").
              Empty string returns all sites.

    Returns:
        JSON with source, count, and flat device list
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        filter_kwargs = {}
        if client.tenant:
            filter_kwargs["tenant"] = client.tenant

        if role:
            resolved = _resolve_filter(client.api.dcim.device_roles, role)
            if not resolved:
                return json.dumps({"error": f"Role not found: '{role}'"}, indent=2)
            filter_kwargs["role"] = resolved

        if site:
            resolved = _resolve_filter(client.api.dcim.sites, site)
            if not resolved:
                return json.dumps({"error": f"Site not found: '{site}'"}, indent=2)
            filter_kwargs["site"] = resolved

        if filter_kwargs:
            raw_devices = list(client.api.dcim.devices.filter(**filter_kwargs))
        else:
            raw_devices = list(client.api.dcim.devices.all())

        devices = []
        for d in raw_devices:
            primary_ip = None
            if d.primary_ip4:
                primary_ip = str(d.primary_ip4.address).split("/")[0]
            devices.append({
                "name": d.name,
                "role": d.role.slug if d.role else None,
                "site": d.site.slug if d.site else None,
                "location": d.location.slug if d.location else None,
                "device_type": d.device_type.model if d.device_type else None,
                "primary_ip": primary_ip,
                "status": d.status.value if d.status else None,
            })

        return json.dumps({
            "source": "netbox",
            "count": len(devices),
            "devices": devices,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query devices: {e}"}, indent=2)


def netbox_get_interfaces(device_name: str) -> str:
    """
    Get all interfaces and their IP addresses for a device.

    Each interface includes its assigned IPs as objects with address, status,
    and VRF fields (not just strings) to support environments with overlapping
    address space.

    Args:
        device_name: Device display name (e.g. "R1"). Must be an exact match.

    Returns:
        JSON with device name, interface count, and interface list
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        device = client.api.dcim.devices.get(name=device_name)
        if not device:
            return json.dumps({"error": f"Device not found: '{device_name}'"}, indent=2)

        interfaces = []
        for intf in client.api.dcim.interfaces.filter(device_id=device.id):
            ip_addresses = []
            for ip in client.api.ipam.ip_addresses.filter(interface_id=intf.id):
                ip_addresses.append({
                    "address": str(ip.address),
                    "status": ip.status.value if ip.status else None,
                    "vrf": ip.vrf.name if ip.vrf else None,
                })

            interfaces.append({
                "name": intf.name,
                "type": intf.type.value if intf.type else None,
                "enabled": intf.enabled,
                "description": intf.description or None,
                "ip_addresses": ip_addresses,
            })

        return json.dumps({
            "device": device_name,
            "interface_count": len(interfaces),
            "interfaces": interfaces,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query interfaces: {e}"}, indent=2)


def netbox_get_prefixes(status: str = "") -> str:
    """
    List IP prefixes from NetBox IPAM.

    Returns prefix, status, description, site, role, and VLAN for each prefix.
    Use this to understand IP address space allocation before suggesting or
    allocating IPs.

    Args:
        status: Filter by prefix status (e.g. "active", "reserved", "deprecated").
                Empty string returns all statuses.

    Returns:
        JSON with count and prefix list
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        if status:
            raw = list(client.api.ipam.prefixes.filter(status=status.lower()))
        else:
            raw = list(client.api.ipam.prefixes.all())

        prefixes = []
        for p in raw:
            prefixes.append({
                "prefix": str(p.prefix),
                "status": p.status.value if p.status else None,
                "description": p.description or None,
                "site": p.site.name if p.site else None,
                "role": p.role.name if p.role else None,
                "vlan": p.vlan.vid if p.vlan else None,
            })

        return json.dumps({"count": len(prefixes), "prefixes": prefixes}, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query prefixes: {e}"}, indent=2)


def netbox_get_ip_addresses(device_name: str = "", prefix: str = "") -> str:
    """
    List IP addresses from NetBox IPAM with optional filters.

    Returns address, status, description, and assignment info (device + interface)
    for each IP. Use device_name to see all IPs on a device, or prefix to see
    all IPs in a subnet.

    Args:
        device_name: Filter by device display name (e.g. "R1"). Empty returns all.
        prefix: Filter by parent prefix in CIDR notation (e.g. "10.255.255.0/24").
                Empty returns all.

    Returns:
        JSON with count and IP address list
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        filter_kwargs = {}

        if device_name:
            device = client.api.dcim.devices.get(name=device_name)
            if not device:
                return json.dumps({"error": f"Device not found: '{device_name}'"}, indent=2)
            filter_kwargs["device_id"] = device.id

        if prefix:
            filter_kwargs["parent"] = prefix

        if filter_kwargs:
            raw = list(client.api.ipam.ip_addresses.filter(**filter_kwargs))
        else:
            raw = list(client.api.ipam.ip_addresses.all())

        ip_list = []
        for ip in raw:
            device_name_val = None
            interface_name = None
            if ip.assigned_object:
                interface_name = ip.assigned_object.name if hasattr(ip.assigned_object, "name") else None
                if hasattr(ip.assigned_object, "device") and ip.assigned_object.device:
                    device_name_val = ip.assigned_object.device.name

            ip_list.append({
                "address": str(ip.address),
                "status": ip.status.value if ip.status else None,
                "description": ip.description or None,
                "device": device_name_val,
                "interface": interface_name,
            })

        return json.dumps({"count": len(ip_list), "ip_addresses": ip_list}, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query IP addresses: {e}"}, indent=2)


def netbox_get_cables(device_name: str = "") -> str:
    """
    List cable connections from NetBox.

    Returns both endpoints (a_side and b_side) for each cable. Use device_name
    to see only cables connected to a specific device.

    Args:
        device_name: Filter cables by device display name (e.g. "R1").
                     Empty string returns all cables.

    Returns:
        JSON with count and cable list
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        if device_name:
            device = client.api.dcim.devices.get(name=device_name)
            if not device:
                return json.dumps({"error": f"Device not found: '{device_name}'"}, indent=2)
            raw = list(client.api.dcim.cables.filter(device_id=device.id))
        else:
            raw = list(client.api.dcim.cables.all())

        cables = []
        for cable in raw:
            def _termination(terms):
                if not terms:
                    return {"device": None, "interface": None}
                t = terms[0]
                return {
                    "device": t.device.name if hasattr(t, "device") and t.device else None,
                    "interface": t.name if hasattr(t, "name") else str(t),
                }

            cables.append({
                "id": cable.id,
                "status": cable.status.value if cable.status else None,
                "label": cable.label or None,
                "a_side": _termination(cable.a_terminations),
                "b_side": _termination(cable.b_terminations),
            })

        return json.dumps({"count": len(cables), "cables": cables}, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to query cables: {e}"}, indent=2)


def netbox_get_hierarchy() -> str:
    """
    Get the full site hierarchy as a nested tree: regions → sites → locations → devices.

    Returns a stable nested structure suitable for rendering topology views
    or understanding where devices are physically located.

    Returns:
        JSON with source and nested regions array
    """
    if not _check_available():
        return _netbox_unavailable_error()

    from config.netbox_client import get_client
    client = get_client()

    try:
        # Gather raw data
        regions = {r.slug: {"name": r.name, "slug": r.slug, "sites": []}
                   for r in client.api.dcim.regions.all()}
        sites = {}
        for s in client.api.dcim.sites.all():
            site_data = {"name": s.name, "slug": s.slug, "locations": []}
            sites[s.slug] = site_data
            region_slug = s.region.slug if s.region else None
            if region_slug and region_slug in regions:
                regions[region_slug]["sites"].append(site_data)

        locations = {}
        for loc in client.api.dcim.locations.all():
            loc_data = {"name": loc.name, "slug": loc.slug, "devices": []}
            locations[loc.slug] = loc_data
            site_slug = loc.site.slug if loc.site else None
            if site_slug and site_slug in sites:
                sites[site_slug]["locations"].append(loc_data)

        # Place devices into locations
        for d in client.api.dcim.devices.all():
            if d.location:
                loc_slug = d.location.slug
                if loc_slug in locations:
                    locations[loc_slug]["devices"].append(d.name)

        return json.dumps({
            "source": "netbox",
            "regions": list(regions.values()),
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Failed to build hierarchy: {e}"}, indent=2)


def netbox_suggest_ip(prefix: str) -> str:
    """
    Preview the next available IP in a prefix without allocating it.

    This is a read-only dry-run tool. Use it to check what IP would be
    allocated before committing. The IP is NOT reserved—another allocation
    could claim it between suggest and allocate.

    Args:
        prefix: CIDR notation prefix (e.g. "10.255.255.0/24")

    Returns:
        JSON with prefix, next available IP, and action confirmation
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not prefix:
        return json.dumps({"error": "prefix is required"}, indent=2)

    from config.netbox_client import get_client
    client = get_client()

    try:
        next_ip = client.get_next_available_ip(prefix)
        return json.dumps({
            "prefix": prefix,
            "next_available": next_ip,
            "action": "preview_only",
        }, indent=2)
    except ValueError as e:
        return json.dumps({"error": str(e), "prefix": prefix}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to query available IPs: {e}"}, indent=2)


def netbox_allocate_ip(
    prefix: str,
    device_name: str = "",
    interface_name: str = "",
    description: str = "",
) -> str:
    """
    Allocate the next available IP from a prefix and optionally assign to a device.

    Creates the IP in NetBox IPAM. If device_name is provided, assigns the IP
    to the specified interface (creating it if needed) and sets it as the
    device's primary IPv4 address.

    Args:
        prefix: CIDR notation prefix to allocate from (e.g. "10.255.255.0/24")
        device_name: Device to assign IP to (display name). Empty = unassigned.
        interface_name: Interface name for assignment (default: GigabitEthernet4).
                        Ignored if device_name is empty.
        description: Optional description for the IP address.

    Returns:
        JSON echoing what was done: action, address, prefix, assignment info, ID
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not prefix:
        return json.dumps({"error": "prefix is required"}, indent=2)

    from config.netbox_client import get_client
    client = get_client()

    try:
        intf = interface_name or ("GigabitEthernet4" if device_name else "")
        alloc = client.allocate_ip(
            prefix=prefix,
            device_name=device_name or None,
            interface_name=intf,
            description=description or None,
        )

        return json.dumps({
            "action": "allocated",
            "address": alloc["address"],
            "prefix": prefix,
            "assigned_to": alloc.get("assigned_to"),
            "set_as_primary": bool(device_name),
            "id": alloc["id"],
        }, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e), "prefix": prefix}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Allocation failed: {e}", "prefix": prefix}, indent=2)


def netbox_release_ip(ip_address: str, force: bool = False) -> str:
    """
    Release an IP address from NetBox IPAM.

    Checks whether the IP is currently assigned to a device interface.
    If assigned, refuses to release unless force=True to prevent accidental
    deallocation of in-use addresses.

    Accepts IP with or without CIDR notation (e.g. "10.255.255.48" or
    "10.255.255.48/24").

    Args:
        ip_address: The IP address to release
        force: Set to True to release even if assigned to a device interface.
               Default False (safe mode).

    Returns:
        JSON with action taken, address, previous status, and assignment info
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not ip_address:
        return json.dumps({"error": "ip_address is required"}, indent=2)

    from config.netbox_client import get_client
    client = get_client()

    try:
        ip_str = ip_address.split("/")[0]

        # Find the IP in NetBox
        ip_obj = None
        for ip in client.api.ipam.ip_addresses.filter(address=ip_str):
            ip_obj = ip
            break

        if not ip_obj:
            return json.dumps({
                "error": f"IP not found in NetBox: {ip_str}",
            }, indent=2)

        # Check assignment status
        assigned_device = None
        assigned_interface = None
        if ip_obj.assigned_object:
            if hasattr(ip_obj.assigned_object, "name"):
                assigned_interface = ip_obj.assigned_object.name
            if hasattr(ip_obj.assigned_object, "device") and ip_obj.assigned_object.device:
                assigned_device = ip_obj.assigned_object.device.name

        previous_status = ip_obj.status.value if ip_obj.status else None
        is_assigned = assigned_device is not None

        # Refuse if assigned and not forced
        if is_assigned and not force:
            return json.dumps({
                "error": (
                    f"IP {ip_str} is assigned to {assigned_device}:{assigned_interface}. "
                    "Use force=true to release assigned IPs."
                ),
                "assigned_to": {
                    "device": assigned_device,
                    "interface": assigned_interface,
                },
            }, indent=2)

        # Delete the IP
        ip_obj.delete()
        client.refresh_cache()

        return json.dumps({
            "action": "released",
            "address": ip_str,
            "previous_status": previous_status,
            "was_assigned": is_assigned,
            "force_used": force if is_assigned else None,
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Release failed: {e}"}, indent=2)


def netbox_refresh_cache() -> str:
    """
    Clear all cached NetBox data.

    This is synchronous and instant—it only clears the in-memory cache dict.
    Cached data repopulates automatically on the next tool call that queries
    NetBox. Use this after making changes directly in the NetBox UI to ensure
    MCP tools reflect the latest state.

    Returns:
        JSON confirming the action and number of cleared entries
    """
    from config.netbox_client import get_client, NETBOX_API_TOKEN

    if not NETBOX_API_TOKEN:
        return json.dumps({"error": "NETBOX_API_TOKEN not configured"}, indent=2)

    try:
        client = get_client()
        cleared = len(client._cache)
        client.refresh_cache()
        return json.dumps({
            "action": "cache_refreshed",
            "cleared_entries": cleared,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Cache refresh failed: {e}"}, indent=2)


def netbox_generate_configs(device_name: str) -> str:
    """
    Generate FRR frr.conf and daemons files from NetBox data.

    Fetches the device's interfaces, IPs, and routing custom fields from
    NetBox, then renders the FRR config files using Jinja2 templates.
    Only works for FRR device types.

    Args:
        device_name: Device display name (e.g. "R9", "edge1"). Must be exact match.

    Returns:
        JSON with device name, frr_conf content, and daemons content
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not device_name:
        return json.dumps({"error": "device_name is required"}, indent=2)

    try:
        import os
        import sys
        import jinja2

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        from scripts.generate_configs import collect_device_data, get_jinja_env

        from config.netbox_client import get_client
        client = get_client()

        context = collect_device_data(client.api, device_name)
        env = get_jinja_env()

        frr_conf = env.get_template("frr.conf.j2").render(**context)
        daemons = env.get_template("daemons.j2").render(**context)

        return json.dumps({
            "device": device_name,
            "frr_conf": frr_conf,
            "daemons": daemons,
        }, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Config generation failed: {e}"}, indent=2)


def netbox_generate_iosxe_config(device_name: str) -> str:
    """
    Generate IOS-XE running-config from NetBox data using Jinja2 templates.

    Fetches the device's interfaces, IPs, and routing custom fields from
    NetBox, then renders the config using the IOS-XE Jinja2 template.
    Only works for C8000V device types with router role.

    Args:
        device_name: Device display name (e.g. "R1", "R6"). Must be exact match.

    Returns:
        JSON with device name and generated running_config content
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not device_name:
        return json.dumps({"error": "device_name is required"}, indent=2)

    try:
        import os
        import sys

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        from scripts.generate_configs import (
            collect_iosxe_device_data,
            get_iosxe_jinja_env,
            render_iosxe_config,
        )

        from config.netbox_client import get_client
        client = get_client()

        context = collect_iosxe_device_data(client.api, device_name)
        env = get_iosxe_jinja_env()
        config = render_iosxe_config(env, context)

        return json.dumps({
            "device": device_name,
            "running_config": config,
        }, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Config generation failed: {e}"}, indent=2)


def netbox_collect_iosxe_config(device_name: str) -> str:
    """
    Collect running-config from an IOS-XE device via SSH, parse it, and push
    structured fields to NetBox custom fields.

    SSHes to the device, runs 'show running-config', parses into structured
    routing fields + verbatim blobs, and updates NetBox. Does NOT modify
    NetBox interfaces or IP addresses.

    Args:
        device_name: Device display name (e.g. "R1", "R6"). Must be exact match.

    Returns:
        JSON with device name, list of updated field names, and any warnings
    """
    if not _check_available():
        return _netbox_unavailable_error()

    if not device_name:
        return json.dumps({"error": "device_name is required"}, indent=2)

    try:
        import asyncio
        import os
        import sys

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)
        from scripts.collect_iosxe_configs import (
            collect_from_device,
            get_device_host,
            parse_running_config,
            push_to_netbox,
        )

        from config.netbox_client import get_client
        client = get_client()

        host = get_device_host(device_name)
        raw = asyncio.run(collect_from_device(device_name, host))
        parsed = parse_running_config(raw)
        updated = push_to_netbox(client.api, device_name, parsed)

        return json.dumps({
            "device": device_name,
            "fields_updated": updated,
            "interfaces_found": len(parsed.get("interfaces_parsed", [])),
        }, indent=2)

    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Collection failed: {e}"}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": netbox_status, "name": "netbox_status", "category": "netbox"},
    {"fn": netbox_get_devices, "name": "netbox_get_devices", "category": "netbox"},
    {"fn": netbox_get_interfaces, "name": "netbox_get_interfaces", "category": "netbox"},
    {"fn": netbox_get_prefixes, "name": "netbox_get_prefixes", "category": "netbox"},
    {"fn": netbox_get_ip_addresses, "name": "netbox_get_ip_addresses", "category": "netbox"},
    {"fn": netbox_get_cables, "name": "netbox_get_cables", "category": "netbox"},
    {"fn": netbox_get_hierarchy, "name": "netbox_get_hierarchy", "category": "netbox"},
    {"fn": netbox_suggest_ip, "name": "netbox_suggest_ip", "category": "netbox"},
    {"fn": netbox_allocate_ip, "name": "netbox_allocate_ip", "category": "netbox"},
    {"fn": netbox_release_ip, "name": "netbox_release_ip", "category": "netbox"},
    {"fn": netbox_refresh_cache, "name": "netbox_refresh_cache", "category": "netbox"},
    {"fn": netbox_generate_configs, "name": "netbox_generate_configs", "category": "netbox"},
    {"fn": netbox_generate_iosxe_config, "name": "netbox_generate_iosxe_config", "category": "netbox"},
    {"fn": netbox_collect_iosxe_config, "name": "netbox_collect_iosxe_config", "category": "netbox"},
]
