"""
Vendor-neutral LLDP topology discovery.

Supports LLDP neighbor discovery across multiple network operating systems:
- Cisco IOS-XE: show lldp neighbors detail
- Arista EOS: show lldp neighbors detail
- Juniper JunOS: show lldp neighbors detail
- Nokia SR Linux: info from state system lldp neighbor
- HPE Aruba CX: show lldp neighbor-info
- Linux (lldpd): lldpctl -f json

Usage:
    from core.lldp import discover_lldp_neighbors, discover_lldp_topology

    # Single device
    neighbors = await discover_lldp_neighbors("R1")

    # Full topology
    topology = await discover_lldp_topology()
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from core.timestamps import isonow

from config.devices import DEVICES, USERNAME, PASSWORD


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class LLDPNeighbor:
    """Standardized LLDP neighbor representation."""
    local_interface: str
    remote_device: str
    remote_interface: str
    remote_ip: Optional[str] = None
    remote_platform: Optional[str] = None
    remote_capabilities: list[str] = field(default_factory=list)
    ttl: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "local_interface": self.local_interface,
            "remote_device": self.remote_device,
            "remote_interface": self.remote_interface,
            "remote_ip": self.remote_ip,
            "remote_platform": self.remote_platform,
            "remote_capabilities": self.remote_capabilities,
            "ttl": self.ttl,
        }


@dataclass
class LLDPDiscoveryResult:
    """Result of LLDP discovery on a single device."""
    device_name: str
    status: str  # success, error, skipped, no_lldp
    neighbors: list[LLDPNeighbor] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: isonow())

    def to_dict(self) -> dict:
        return {
            "device": self.device_name,
            "status": self.status,
            "neighbor_count": len(self.neighbors),
            "neighbors": [n.to_dict() for n in self.neighbors],
            "error": self.error,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Vendor-Specific Parsers
# =============================================================================

def _parse_cisco_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse Cisco IOS-XE/IOS 'show lldp neighbors detail' output."""
    neighbors = []

    # Split by separator line
    blocks = re.split(r'-{20,}', output)

    for block in blocks:
        if "Local Intf:" not in block and "Local Interface:" not in block:
            continue

        neighbor = {}

        # Local interface
        local_match = re.search(r'Local Intf(?:erface)?:\s*(\S+)', block)
        if local_match:
            neighbor["local_interface"] = _normalize_interface(local_match.group(1))
        else:
            continue

        # Chassis ID / System Name (device ID)
        chassis_match = re.search(r'Chassis id:\s*(.+)', block)
        system_match = re.search(r'System Name:\s*(\S+)', block)
        if system_match:
            neighbor["remote_device"] = system_match.group(1).split('.')[0]
        elif chassis_match:
            neighbor["remote_device"] = chassis_match.group(1).strip()
        else:
            continue

        # Port ID (remote interface)
        port_match = re.search(r'Port id:\s*(.+)', block)
        if port_match:
            neighbor["remote_interface"] = _normalize_interface(port_match.group(1).strip())
        else:
            neighbor["remote_interface"] = "unknown"

        # Management Address
        mgmt_match = re.search(r'Management Addresses?:\s*(?:IP:\s*)?(\d+\.\d+\.\d+\.\d+)', block)
        if mgmt_match:
            neighbor["remote_ip"] = mgmt_match.group(1)

        # System Description (platform)
        desc_match = re.search(r'System Description:\s*\n?\s*(.+?)(?:\n\n|\nTime|$)', block, re.DOTALL)
        if desc_match:
            neighbor["remote_platform"] = desc_match.group(1).strip()[:100]

        # Capabilities
        caps_match = re.search(r'System Capabilities:\s*(.+)', block)
        if caps_match:
            neighbor["remote_capabilities"] = [c.strip() for c in caps_match.group(1).split(',')]

        # TTL
        ttl_match = re.search(r'Time remaining:\s*(\d+)', block)
        if ttl_match:
            neighbor["ttl"] = int(ttl_match.group(1))

        neighbors.append(LLDPNeighbor(**neighbor))

    return neighbors


def _parse_arista_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse Arista EOS 'show lldp neighbors detail' output."""
    neighbors = []

    # Arista format is similar to Cisco but with some differences
    blocks = re.split(r'Interface\s+Ethernet', output)

    for block in blocks[1:]:  # Skip first empty block
        neighbor = {}

        # Local interface (Ethernet prefix was split)
        intf_match = re.match(r'(\d+(?:/\d+)*)', block)
        if intf_match:
            neighbor["local_interface"] = f"Ethernet{intf_match.group(1)}"
        else:
            continue

        # System Name
        name_match = re.search(r'System Name:\s*"?([^"\n]+)"?', block)
        if name_match:
            neighbor["remote_device"] = name_match.group(1).strip().split('.')[0]
        else:
            chassis_match = re.search(r'Chassis ID:\s*"?([^"\n]+)"?', block)
            if chassis_match:
                neighbor["remote_device"] = chassis_match.group(1).strip()
            else:
                continue

        # Port ID
        port_match = re.search(r'Port ID\s*:\s*"?([^"\n]+)"?', block)
        if port_match:
            neighbor["remote_interface"] = _normalize_interface(port_match.group(1).strip())
        else:
            neighbor["remote_interface"] = "unknown"

        # Management Address
        mgmt_match = re.search(r'Management Address:\s*(\d+\.\d+\.\d+\.\d+)', block)
        if mgmt_match:
            neighbor["remote_ip"] = mgmt_match.group(1)

        # System Description
        desc_match = re.search(r'System Description:\s*"?([^"\n]+)"?', block)
        if desc_match:
            neighbor["remote_platform"] = desc_match.group(1).strip()

        neighbors.append(LLDPNeighbor(**neighbor))

    return neighbors


def _parse_juniper_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse Juniper JunOS 'show lldp neighbors' output."""
    neighbors = []

    # Juniper can have tabular or detailed output
    # Try detailed first
    if "Local Interface" in output and ":" in output:
        blocks = re.split(r'Local Interface\s*:', output)
        for block in blocks[1:]:
            neighbor = {}

            # Local interface is at the start
            lines = block.strip().split('\n')
            if lines:
                neighbor["local_interface"] = _normalize_interface(lines[0].split()[0])

            # Parse key-value pairs
            for line in lines:
                if "System Name" in line:
                    match = re.search(r'System Name\s*:\s*(\S+)', line)
                    if match:
                        neighbor["remote_device"] = match.group(1).split('.')[0]
                elif "Port ID" in line:
                    match = re.search(r'Port ID\s*:\s*(.+)', line)
                    if match:
                        neighbor["remote_interface"] = _normalize_interface(match.group(1).strip())
                elif "Port description" in line:
                    match = re.search(r'Port description\s*:\s*(.+)', line)
                    if match:
                        neighbor["remote_interface"] = _normalize_interface(match.group(1).strip())
                elif "Management address" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        neighbor["remote_ip"] = match.group(1)

            if "remote_device" in neighbor:
                if "remote_interface" not in neighbor:
                    neighbor["remote_interface"] = "unknown"
                neighbors.append(LLDPNeighbor(**neighbor))
    else:
        # Tabular format
        for line in output.split('\n'):
            if not line.strip() or 'Local Interface' in line or '---' in line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                neighbor = {
                    "local_interface": _normalize_interface(parts[0]),
                    "remote_device": parts[1].split('.')[0],
                    "remote_interface": _normalize_interface(parts[2]) if len(parts) > 2 else "unknown",
                }
                neighbors.append(LLDPNeighbor(**neighbor))

    return neighbors


def _parse_nokia_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse Nokia SR Linux LLDP output."""
    neighbors = []

    # Try to parse as JSON first (modern SR Linux)
    try:
        data = json.loads(output)
        # Navigate Nokia JSON structure
        lldp_data = data.get("system", {}).get("lldp", {}).get("neighbor", {})
        for intf, intf_data in lldp_data.items():
            for idx, nbr in intf_data.items():
                neighbor = {
                    "local_interface": intf,
                    "remote_device": nbr.get("system-name", nbr.get("chassis-id", "unknown")),
                    "remote_interface": nbr.get("port-id", "unknown"),
                    "remote_ip": nbr.get("management-address", [{}])[0].get("address") if nbr.get("management-address") else None,
                    "remote_platform": nbr.get("system-description"),
                }
                neighbors.append(LLDPNeighbor(**neighbor))
        return neighbors
    except (json.JSONDecodeError, AttributeError):
        pass

    # CLI table format
    current_intf = None
    for line in output.split('\n'):
        if 'ethernet-' in line.lower():
            intf_match = re.search(r'(ethernet-\d+/\d+)', line, re.IGNORECASE)
            if intf_match:
                current_intf = intf_match.group(1)

        if current_intf and ('system-name' in line.lower() or 'chassis-id' in line.lower()):
            name_match = re.search(r'(?:system-name|chassis-id)\s+(\S+)', line, re.IGNORECASE)
            if name_match:
                neighbor = {
                    "local_interface": current_intf,
                    "remote_device": name_match.group(1).split('.')[0],
                    "remote_interface": "unknown",
                }
                neighbors.append(LLDPNeighbor(**neighbor))

    return neighbors


def _parse_linux_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse Linux lldpctl output (JSON or text)."""
    neighbors = []

    # Try JSON format first (lldpctl -f json)
    try:
        data = json.loads(output)
        lldp_data = data.get("lldp", [{}])[0].get("interface", [])
        for intf in lldp_data:
            intf_name = list(intf.keys())[0]
            chassis = intf[intf_name].get("chassis", {})
            port = intf[intf_name].get("port", {})

            # Get chassis name or ID
            chassis_data = list(chassis.values())[0] if chassis else {}
            remote_name = chassis_data.get("name", chassis_data.get("id", {}).get("value", "unknown"))

            # Get port description or ID
            remote_port = port.get("descr", port.get("id", {}).get("value", "unknown"))

            neighbor = {
                "local_interface": intf_name,
                "remote_device": remote_name.split('.')[0] if remote_name else "unknown",
                "remote_interface": _normalize_interface(remote_port),
                "remote_ip": chassis_data.get("mgmt-ip"),
                "remote_platform": chassis_data.get("descr"),
            }
            neighbors.append(LLDPNeighbor(**neighbor))
        return neighbors
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    # Text format
    current_intf = None
    current_neighbor = {}

    for line in output.split('\n'):
        if line.startswith('Interface:'):
            if current_neighbor and "remote_device" in current_neighbor:
                neighbors.append(LLDPNeighbor(**current_neighbor))
            match = re.search(r'Interface:\s*(\S+)', line)
            if match:
                current_intf = match.group(1)
                current_neighbor = {"local_interface": current_intf, "remote_interface": "unknown"}
        elif 'SysName:' in line:
            match = re.search(r'SysName:\s*(.+)', line)
            if match:
                current_neighbor["remote_device"] = match.group(1).strip().split('.')[0]
        elif 'PortID:' in line or 'PortDescr:' in line:
            match = re.search(r'(?:PortID|PortDescr):\s*(.+)', line)
            if match:
                current_neighbor["remote_interface"] = _normalize_interface(match.group(1).strip())
        elif 'MgmtIP:' in line:
            match = re.search(r'MgmtIP:\s*(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                current_neighbor["remote_ip"] = match.group(1)
        elif 'SysDescr:' in line:
            match = re.search(r'SysDescr:\s*(.+)', line)
            if match:
                current_neighbor["remote_platform"] = match.group(1).strip()

    # Don't forget the last neighbor
    if current_neighbor and "remote_device" in current_neighbor:
        neighbors.append(LLDPNeighbor(**current_neighbor))

    return neighbors


def _parse_hpe_lldp(output: str) -> list[LLDPNeighbor]:
    """Parse HPE Aruba CX / ProCurve LLDP output."""
    neighbors = []

    # Aruba CX format
    blocks = re.split(r'Neighbor Entry \d+', output)

    for block in blocks:
        if "Local Port" not in block and "Local-port" not in block:
            continue

        neighbor = {}

        # Local port
        local_match = re.search(r'Local[- ]Port\s*:\s*(\S+)', block, re.IGNORECASE)
        if local_match:
            neighbor["local_interface"] = _normalize_interface(local_match.group(1))
        else:
            continue

        # System Name / Chassis ID
        name_match = re.search(r'System-?Name\s*:\s*(\S+)', block, re.IGNORECASE)
        if name_match:
            neighbor["remote_device"] = name_match.group(1).split('.')[0]
        else:
            chassis_match = re.search(r'Chassis-?ID\s*:\s*(\S+)', block, re.IGNORECASE)
            if chassis_match:
                neighbor["remote_device"] = chassis_match.group(1)
            else:
                continue

        # Remote Port
        port_match = re.search(r'Port-?ID\s*:\s*(.+)', block, re.IGNORECASE)
        if port_match:
            neighbor["remote_interface"] = _normalize_interface(port_match.group(1).strip())
        else:
            neighbor["remote_interface"] = "unknown"

        # Management Address
        mgmt_match = re.search(r'Management-?Address\s*:\s*(\d+\.\d+\.\d+\.\d+)', block)
        if mgmt_match:
            neighbor["remote_ip"] = mgmt_match.group(1)

        neighbors.append(LLDPNeighbor(**neighbor))

    return neighbors


def _normalize_interface(intf: str) -> str:
    """Normalize interface names to consistent short format."""
    if not intf:
        return "unknown"

    intf = intf.strip()

    # Cisco interface normalization
    replacements = [
        (r'^GigabitEthernet', 'Gi'),
        (r'^FastEthernet', 'Fa'),
        (r'^TenGigabitEthernet', 'Te'),
        (r'^TwentyFiveGigE', 'Twe'),
        (r'^FortyGigabitEthernet', 'Fo'),
        (r'^HundredGigE', 'Hu'),
        (r'^Loopback', 'Lo'),
        (r'^Tunnel', 'Tu'),
        (r'^Port-channel', 'Po'),
        (r'^Vlan', 'Vl'),
    ]

    for pattern, replacement in replacements:
        intf = re.sub(pattern, replacement, intf, flags=re.IGNORECASE)

    return intf


# =============================================================================
# LLDP Command Mapping
# =============================================================================

LLDP_COMMANDS = {
    "cisco_xe": "show lldp neighbors detail",
    "cisco_ios": "show lldp neighbors detail",
    "arista_eos": "show lldp neighbors detail",
    "juniper_junos": "show lldp neighbors",
    "nokia_srl": "info from state system lldp neighbor",
    "hp_procurve": "show lldp info remote-device",
    "aruba_aoscx": "show lldp neighbor-info detail",
    "hp_comware": "display lldp neighbor-information",
    "linux": "lldpctl -f json",
    # Containerlab devices
    "containerlab_srlinux": "info from state system lldp neighbor",
    "containerlab_frr": None,  # FRRouting doesn't have built-in LLDP
    "containerlab_linux": "lldpctl -f json",
}

LLDP_PARSERS = {
    "cisco_xe": _parse_cisco_lldp,
    "cisco_ios": _parse_cisco_lldp,
    "arista_eos": _parse_arista_lldp,
    "juniper_junos": _parse_juniper_lldp,
    "nokia_srl": _parse_nokia_lldp,
    "hp_procurve": _parse_hpe_lldp,
    "aruba_aoscx": _parse_hpe_lldp,
    "hp_comware": _parse_cisco_lldp,  # Similar format
    "linux": _parse_linux_lldp,
    # Containerlab devices
    "containerlab_srlinux": _parse_nokia_lldp,
    "containerlab_linux": _parse_linux_lldp,
}


# =============================================================================
# Discovery Functions
# =============================================================================

async def _get_lldp_output(device_name: str, device: dict) -> tuple[str, str]:
    """Get LLDP output from device using appropriate method.

    Returns:
        Tuple of (output, device_type)
    """
    device_type = device.get("device_type", "")
    host = device.get("host", "")

    # Get the appropriate LLDP command
    lldp_command = LLDP_COMMANDS.get(device_type)

    if not lldp_command:
        raise ValueError(f"LLDP not supported for device type: {device_type}")

    # Use Scrapli for Cisco IOS-XE
    if device_type == "cisco_xe":
        from core.scrapli_manager import get_ios_xe_connection
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(lldp_command)
            return response.result, device_type

    # Use Netmiko for HPE devices
    if device_type in ("aruba_aoscx", "hp_procurve", "hp_comware"):
        from core.netmiko_manager import send_command_netmiko
        response = await send_command_netmiko(device_name, lldp_command)
        return response.result, device_type

    # Use SSH for Linux
    if device_type == "linux":
        import asyncssh
        try:
            async with asyncssh.connect(
                host,
                username=USERNAME,
                password=PASSWORD,
                known_hosts=None,
            ) as conn:
                result = await conn.run(lldp_command, timeout=10)
                return result.stdout, device_type
        except Exception as e:
            raise RuntimeError(f"SSH connection failed: {e}")

    # For containerlab devices, use special handling
    if device_type.startswith("containerlab_"):
        from core.containerlab import get_containerlab_command_output
        return await get_containerlab_command_output(device_name, lldp_command), device_type

    raise ValueError(f"No connection method for device type: {device_type}")


async def discover_lldp_neighbors(device_name: str) -> LLDPDiscoveryResult:
    """Discover LLDP neighbors on a single device.

    Args:
        device_name: Name of the device from inventory

    Returns:
        LLDPDiscoveryResult with neighbors and status
    """
    if device_name not in DEVICES:
        return LLDPDiscoveryResult(
            device_name=device_name,
            status="error",
            error=f"Device '{device_name}' not found in inventory"
        )

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    # Check if LLDP is supported
    if device_type not in LLDP_COMMANDS:
        return LLDPDiscoveryResult(
            device_name=device_name,
            status="skipped",
            error=f"LLDP not supported for device type: {device_type}"
        )

    # For containerlab devices without LLDP (e.g., FRRouting), mark as healthy
    # The actual health check can be done via /api/containerlab-health/<device>
    # This avoids subprocess issues in async/threaded contexts
    if LLDP_COMMANDS.get(device_type) is None:
        return LLDPDiscoveryResult(
            device_name=device_name,
            status="success",
            neighbors=[],  # No LLDP neighbors for this device type
            error=None
        )

    try:
        output, dtype = await _get_lldp_output(device_name, device)

        # Check for common "no LLDP" messages
        no_lldp_indicators = [
            "lldp is not enabled",
            "lldp not enabled",
            "no lldp entries",
            "% lldp",
            "lldp run",
            "lldpd is not running",
        ]

        output_lower = output.lower()
        if any(ind in output_lower for ind in no_lldp_indicators):
            return LLDPDiscoveryResult(
                device_name=device_name,
                status="no_lldp",
                error="LLDP not enabled on device"
            )

        # Parse with appropriate parser
        parser = LLDP_PARSERS.get(dtype, _parse_cisco_lldp)
        neighbors = parser(output)

        return LLDPDiscoveryResult(
            device_name=device_name,
            status="success",
            neighbors=neighbors
        )
    except Exception as e:
        # For containerlab devices, fall back to container health check
        if device_type.startswith("containerlab_"):
            try:
                from core.containerlab import check_health_status
                health = check_health_status(device_name)
                return LLDPDiscoveryResult(
                    device_name=device_name,
                    status="success" if health == "healthy" else "error",
                    neighbors=[],
                    error=None if health == "healthy" else f"LLDP failed, container: {health}"
                )
            except Exception:
                pass  # Fall through to error return

        return LLDPDiscoveryResult(
            device_name=device_name,
            status="error",
            error=str(e)
        )


async def discover_lldp_topology(
    devices: list[str] = None,
    max_concurrent: int = 10
) -> dict:
    """Discover full network topology using LLDP.

    Args:
        devices: List of device names (default: all devices)
        max_concurrent: Maximum concurrent connections

    Returns:
        Dict with topology graph (nodes, links) and discovery results
    """
    import time
    start = time.time()

    if devices is None:
        devices = list(DEVICES.keys())

    # Limit concurrency
    semaphore = asyncio.Semaphore(max_concurrent)

    async def discover_with_limit(device_name: str) -> LLDPDiscoveryResult:
        async with semaphore:
            return await discover_lldp_neighbors(device_name)

    # Run discovery on all devices
    tasks = [discover_with_limit(name) for name in devices]
    results = await asyncio.gather(*tasks)

    # Build topology
    nodes = {}
    links = []
    link_set = set()  # Deduplicate bidirectional links

    # First pass: create nodes
    for device_name in devices:
        device = DEVICES.get(device_name, {})
        device_type = device.get("device_type", "unknown")

        # Determine platform
        if device_type == "cisco_xe":
            if device_name.startswith("R"):
                platform = "C8000V"
            elif device_name.startswith("Switch"):
                platform = "Cat9kv"
            else:
                platform = "IOS-XE"
        elif device_type == "linux":
            platform = "Linux"
        elif device_type.startswith("containerlab"):
            platform = device_type.replace("containerlab_", "")
        elif device_type.startswith("aruba"):
            platform = "Aruba CX"
        elif device_type.startswith("hp_"):
            platform = "HPE ProCurve"
        else:
            platform = device_type

        nodes[device_name] = {
            "id": device_name,
            "platform": platform,
            "ip": device.get("host", ""),
            "status": "unknown",
        }

    # Second pass: add links and update status
    for result in results:
        if result.status == "success":
            nodes[result.device_name]["status"] = "healthy"

            for neighbor in result.neighbors:
                # Skip self-links
                if neighbor.remote_device == result.device_name:
                    continue

                # Create link ID (sorted to deduplicate bidirectional)
                link_pair = tuple(sorted([result.device_name, neighbor.remote_device]))

                if link_pair not in link_set:
                    link_set.add(link_pair)
                    links.append({
                        "source": result.device_name,
                        "target": neighbor.remote_device,
                        "source_interface": neighbor.local_interface,
                        "target_interface": neighbor.remote_interface,
                    })

                    # Add discovered neighbor to nodes if not already present
                    if neighbor.remote_device not in nodes:
                        nodes[neighbor.remote_device] = {
                            "id": neighbor.remote_device,
                            "platform": neighbor.remote_platform or "unknown",
                            "ip": neighbor.remote_ip or "",
                            "status": "discovered",  # Discovered via LLDP, not directly polled
                        }
        elif result.status == "skipped" or result.status == "no_lldp":
            nodes[result.device_name]["status"] = "no_lldp"
        else:
            nodes[result.device_name]["status"] = "error"

    elapsed = time.time() - start

    # Summary
    summary = {
        "total_devices": len(devices),
        "success": sum(1 for r in results if r.status == "success"),
        "no_lldp": sum(1 for r in results if r.status == "no_lldp"),
        "skipped": sum(1 for r in results if r.status == "skipped"),
        "errors": sum(1 for r in results if r.status == "error"),
        "total_links": len(links),
        "discovered_devices": len([n for n in nodes.values() if n["status"] == "discovered"]),
    }

    return {
        "topology": {
            "nodes": list(nodes.values()),
            "links": links,
        },
        "discovery_results": [r.to_dict() for r in results],
        "summary": summary,
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": isonow(),
    }


# =============================================================================
# Utility Functions
# =============================================================================

async def check_lldp_enabled(device_name: str) -> dict:
    """Check if LLDP is enabled on a device.

    Returns:
        Dict with enabled status and configuration details
    """
    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found"}

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    if device_type == "cisco_xe":
        from core.scrapli_manager import get_ios_xe_connection
        try:
            async with get_ios_xe_connection(device_name) as conn:
                response = await conn.send_command("show lldp")
                output = response.result

                # Parse LLDP status
                enabled = "LLDP is not enabled" not in output

                # Get timer values if enabled
                holdtime = None
                timer = None
                if enabled:
                    holdtime_match = re.search(r'Holdtime:\s*(\d+)', output)
                    timer_match = re.search(r'Timer:\s*(\d+)', output)
                    if holdtime_match:
                        holdtime = int(holdtime_match.group(1))
                    if timer_match:
                        timer = int(timer_match.group(1))

                return {
                    "device": device_name,
                    "lldp_enabled": enabled,
                    "holdtime_seconds": holdtime,
                    "timer_seconds": timer,
                }
        except Exception as e:
            return {"device": device_name, "error": str(e)}

    return {"device": device_name, "error": f"LLDP check not implemented for {device_type}"}


async def enable_lldp(device_name: str) -> dict:
    """Enable LLDP globally on a Cisco device.

    Returns:
        Dict with result of configuration
    """
    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found"}

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    if device_type != "cisco_xe":
        return {"error": "LLDP enable only supported for Cisco IOS-XE devices"}

    from core.scrapli_manager import get_ios_xe_connection
    try:
        async with get_ios_xe_connection(device_name) as conn:
            # Enable LLDP globally
            response = await conn.send_configs(["lldp run"])

            # Verify
            verify_response = await conn.send_command("show lldp")
            enabled = "LLDP is not enabled" not in verify_response.result

            return {
                "device": device_name,
                "success": enabled,
                "message": "LLDP enabled successfully" if enabled else "Failed to enable LLDP",
            }
    except Exception as e:
        return {"device": device_name, "error": str(e)}
