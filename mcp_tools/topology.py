"""
Topology discovery MCP tools.

This module provides tools for discovering network topology:
- discover_topology: Discover topology using LLDP or CDP
- lldp_neighbors: Get LLDP neighbors from a device
- lldp_check_status: Check if LLDP is enabled
- lldp_enable: Enable LLDP on a device
- lldp_supported_platforms: List supported LLDP platforms
"""

import asyncio
import json
import re
import time

from config.devices import DEVICES, get_scrapli_device
from core import log_event
from core.device_cache import get_device_cache
from core.lldp import (
    discover_lldp_neighbors,
    discover_lldp_topology,
    check_lldp_enabled,
    enable_lldp,
    LLDP_COMMANDS,
)

from mcp_tools._shared import throttled


# =============================================================================
# Internal Helper Functions
# =============================================================================

async def _get_cdp_neighbors(name: str, device: dict) -> dict:
    """Get CDP neighbors from a Cisco device."""
    from core.scrapli_manager import get_ios_xe_connection

    device_type = device.get("device_type", "")

    # Skip non-Cisco devices
    if device_type != "cisco_xe":
        return {"device": name, "status": "skipped", "output": ""}

    try:
        async with get_ios_xe_connection(name) as conn:
            response = await conn.send_command("show cdp neighbors detail")
        return {"device": name, "status": "success", "output": response.result}
    except Exception as e:
        return {"device": name, "status": "error", "error": str(e)}


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def discover_topology(protocol: str = "lldp") -> str:
    """
    Discover network topology using LLDP (default) or CDP.

    LLDP is vendor-neutral and works across:
    - Cisco IOS-XE/IOS
    - Arista EOS
    - Juniper JunOS
    - Nokia SR Linux
    - HPE Aruba CX / ProCurve / Comware
    - Linux (with lldpd)

    CDP is Cisco-proprietary but may have more detail for Cisco-only networks.

    Args:
        protocol: "lldp" (default, vendor-neutral) or "cdp" (Cisco-only)

    Returns:
        JSON with topology graph (nodes, links) and discovery metadata
    """
    start = time.time()

    protocol = protocol.lower()
    if protocol not in ("lldp", "cdp"):
        return json.dumps({"error": f"Invalid protocol '{protocol}'. Use 'lldp' or 'cdp'."})

    # Check cache first - topology changes infrequently
    cache = get_device_cache()
    cached_topology = await cache.get_topology()
    if cached_topology and cached_topology.get("_protocol") == protocol:
        cached_topology['_from_cache'] = True
        return json.dumps(cached_topology, indent=2)

    # Use LLDP discovery (vendor-neutral, default)
    if protocol == "lldp":
        result = await discover_lldp_topology()
        topology_result = {
            "_protocol": "lldp",
            "elapsed_seconds": result["elapsed_seconds"],
            "nodes": result["topology"]["nodes"],
            "links": result["topology"]["links"],
            "summary": result["summary"],
        }
        # Cache the topology for future requests (TTL: 120s)
        await cache.set_topology(topology_result)
        return json.dumps(topology_result, indent=2)

    # Fall back to CDP discovery (Cisco-only)
    # Query all Cisco devices in parallel with throttling
    tasks = [throttled(_get_cdp_neighbors(name, get_scrapli_device(name))) for name in DEVICES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Build nodes dict
    nodes = {}
    for device_name, device in DEVICES.items():
        device_type = device.get("device_type", "")
        if device_type == "cisco_xe":
            if device_name.startswith("R"):
                platform = "C8000V"
            else:
                platform = "Cat9kv"
        elif device_type == "linux":
            platform = "Linux"
        elif device_type == "containerlab_srlinux":
            platform = "Nokia SR Linux"
        elif device_type == "containerlab_frr":
            platform = "FRRouting"
        elif device_type == "containerlab_linux":
            platform = "Alpine (clab)"
        else:
            platform = "unknown"

        nodes[device_name] = {
            "id": device_name,
            "ip": device.get("host", "unknown"),
            "platform": platform,
            "status": "unknown"
        }

    # Parse CDP output and build links
    links = []
    seen_links = set()

    for result in results:
        if isinstance(result, Exception):
            continue

        device_name = result["device"]

        if result["status"] == "success":
            nodes[device_name]["status"] = "healthy"
        elif result["status"] == "skipped":
            continue
        else:
            nodes[device_name]["status"] = "critical"
            continue

        cdp_output = result["output"]
        neighbor_blocks = cdp_output.split("-------------------------")

        for block in neighbor_blocks:
            if "Device ID:" not in block:
                continue

            device_id_match = re.search(r"Device ID:\s*(\S+)", block)
            if not device_id_match:
                continue
            neighbor_name = device_id_match.group(1).split('.')[0]

            local_intf_match = re.search(r"Interface:\s*(\S+),", block)
            local_intf = local_intf_match.group(1) if local_intf_match else "unknown"

            remote_intf_match = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
            remote_intf = remote_intf_match.group(1) if remote_intf_match else "unknown"

            ip_match = re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", block)
            neighbor_ip = ip_match.group(1) if ip_match else "unknown"

            platform_match = re.search(r"Platform:\s*[Cc]isco\s*(\S+)", block)
            platform = platform_match.group(1) if platform_match else "unknown"

            if neighbor_name not in nodes:
                nodes[neighbor_name] = {
                    "id": neighbor_name,
                    "ip": neighbor_ip,
                    "platform": platform,
                    "status": "unknown"
                }

            link_key = tuple(sorted([device_name, neighbor_name]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                links.append({
                    "source": device_name,
                    "target": neighbor_name,
                    "source_intf": local_intf,
                    "target_intf": remote_intf
                })

    elapsed = time.time() - start

    topology_result = {
        "_protocol": "cdp",
        "elapsed_seconds": round(elapsed, 2),
        "nodes": list(nodes.values()),
        "links": links
    }

    # Cache the topology for future requests (TTL: 120s)
    await cache.set_topology(topology_result)

    return json.dumps(topology_result, indent=2)


async def lldp_neighbors(device_name: str) -> str:
    """
    Get LLDP neighbors from a single device.

    Supports multiple vendors with automatic command and parser selection:
    - Cisco: show lldp neighbors detail
    - Arista: show lldp neighbors detail
    - Juniper: show lldp neighbors
    - Nokia: info from state system lldp neighbor
    - HPE: show lldp neighbor-info detail
    - Linux: lldpctl -f json

    Args:
        device_name: Name of the device to query

    Returns:
        JSON with neighbor list and discovery status
    """
    result = await discover_lldp_neighbors(device_name)
    return json.dumps(result.to_dict(), indent=2)


async def lldp_check_status(device_name: str) -> str:
    """
    Check if LLDP is enabled on a device.

    Args:
        device_name: Device to check

    Returns:
        JSON with LLDP status and timer configuration
    """
    result = await check_lldp_enabled(device_name)
    return json.dumps(result, indent=2)


async def lldp_enable(device_name: str) -> str:
    """
    Enable LLDP globally on a Cisco IOS-XE device.

    Note: This is a configuration change. Use with caution.

    Args:
        device_name: Device to configure

    Returns:
        JSON with configuration result
    """
    result = await enable_lldp(device_name)

    # Log the configuration change
    log_event(
        action="lldp_enable",
        device=device_name,
        details=f"LLDP enable: {result.get('message', result.get('error', 'unknown'))}",
        status="success" if result.get("success") else "error"
    )

    return json.dumps(result, indent=2)


async def lldp_supported_platforms() -> str:
    """
    List platforms that support LLDP discovery.

    Returns:
        JSON with supported device types and their LLDP commands
    """
    platforms = []
    for device_type, command in LLDP_COMMANDS.items():
        platforms.append({
            "device_type": device_type,
            "lldp_command": command,
            "devices_in_inventory": [
                name for name, dev in DEVICES.items()
                if dev.get("device_type") == device_type
            ]
        })

    return json.dumps({
        "supported_platforms": platforms,
        "total_platforms": len(LLDP_COMMANDS),
    }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": discover_topology, "name": "discover_topology", "category": "topology"},
    {"fn": lldp_neighbors, "name": "lldp_neighbors", "category": "topology"},
    {"fn": lldp_check_status, "name": "lldp_check_status", "category": "topology"},
    {"fn": lldp_enable, "name": "lldp_enable", "category": "topology"},
    {"fn": lldp_supported_platforms, "name": "lldp_supported_platforms", "category": "topology"},
]
