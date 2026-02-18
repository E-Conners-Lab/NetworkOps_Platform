"""
Routing operations: routing table, neighbor discovery.
"""
import json
import re

from config.devices import DEVICES
from core.scrapli_manager import get_ios_xe_connection
from ._ops_helpers import is_cisco_device


async def get_routing_table(device_name: str, protocol: str = None, prefix: str = None) -> str:
    """
    Get parsed routing table from a device.

    Args:
        device_name: Device to query
        protocol: Filter by protocol (ospf, bgp, eigrp, static, connected)
        prefix: Filter by prefix (e.g., "10.0.0.0" or "10.0.0.0/24")

    Returns:
        JSON with structured routing entries
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Routing table only supported for IOS-XE devices"})

    # Build command
    if protocol:
        cmd = f"show ip route {protocol}"
    elif prefix:
        cmd = f"show ip route {prefix}"
    else:
        cmd = "show ip route"

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(cmd)
            output = response.result

        # Parse routing table
        routes = []
        protocol_map = {
            'C': 'connected', 'L': 'local', 'S': 'static',
            'O': 'ospf', 'O IA': 'ospf-ia', 'O E1': 'ospf-e1', 'O E2': 'ospf-e2',
            'D': 'eigrp', 'D EX': 'eigrp-ex',
            'B': 'bgp', 'i': 'isis'
        }

        for line in output.splitlines():
            # Match route lines: "O    10.0.12.0/30 [110/2] via 10.0.13.1, 01:23:45, GigabitEthernet2"
            route_match = re.match(
                r'^([A-Z][A-Z]?(?:\s+[A-Z][A-Z]?)?)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+'
                r'(?:\[(\d+)/(\d+)\])?\s*'
                r'(?:via\s+(\d+\.\d+\.\d+\.\d+),?\s*)?'
                r'(?:(\S+),?\s*)?'
                r'(\S+)?',
                line.strip()
            )

            if route_match:
                proto_code = route_match.group(1).strip()
                routes.append({
                    "prefix": route_match.group(2),
                    "protocol": protocol_map.get(proto_code, proto_code),
                    "admin_distance": int(route_match.group(3)) if route_match.group(3) else None,
                    "metric": int(route_match.group(4)) if route_match.group(4) else None,
                    "next_hop": route_match.group(5),
                    "interface": route_match.group(7) or route_match.group(6)
                })

        # Count by protocol
        protocol_counts = {}
        for route in routes:
            proto = route["protocol"]
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        return json.dumps({
            "device": device_name,
            "filter": {"protocol": protocol, "prefix": prefix},
            "total_routes": len(routes),
            "by_protocol": protocol_counts,
            "routes": routes
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


async def get_neighbors(device_name: str, protocol: str = "cdp") -> str:
    """
    Get structured neighbor discovery data (CDP or LLDP).

    Args:
        device_name: Device to query
        protocol: "cdp" or "lldp" (default: cdp)

    Returns:
        JSON with parsed neighbor information
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Neighbor discovery only supported for IOS-XE devices"})

    if protocol.lower() == "lldp":
        cmd = "show lldp neighbors detail"
    else:
        cmd = "show cdp neighbors detail"

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(cmd)
            output = response.result

        neighbors = []

        if protocol.lower() == "lldp":
            # Parse LLDP blocks
            blocks = output.split("------------------------------------------------")
            for block in blocks:
                if "Local Intf:" not in block:
                    continue

                neighbor = {}
                local_match = re.search(r'Local Intf:\s*(\S+)', block)
                if local_match:
                    neighbor["local_interface"] = local_match.group(1)

                chassis_match = re.search(r'Chassis id:\s*(\S+)', block)
                if chassis_match:
                    neighbor["chassis_id"] = chassis_match.group(1)

                port_match = re.search(r'Port id:\s*(\S+)', block)
                if port_match:
                    neighbor["remote_port"] = port_match.group(1)

                name_match = re.search(r'System Name:\s*(\S+)', block)
                if name_match:
                    neighbor["system_name"] = name_match.group(1)

                if neighbor:
                    neighbors.append(neighbor)
        else:
            # Parse CDP blocks
            blocks = output.split("-------------------------")
            for block in blocks:
                if "Device ID:" not in block:
                    continue

                neighbor = {}
                device_match = re.search(r'Device ID:\s*(\S+)', block)
                if device_match:
                    neighbor["device_id"] = device_match.group(1).split('.')[0]

                local_match = re.search(r'Interface:\s*(\S+),', block)
                if local_match:
                    neighbor["local_interface"] = local_match.group(1)

                remote_match = re.search(r'Port ID \(outgoing port\):\s*(\S+)', block)
                if remote_match:
                    neighbor["remote_port"] = remote_match.group(1)

                ip_match = re.search(r'IP address:\s*(\d+\.\d+\.\d+\.\d+)', block)
                if ip_match:
                    neighbor["ip_address"] = ip_match.group(1)

                platform_match = re.search(r'Platform:\s*([^,]+)', block)
                if platform_match:
                    neighbor["platform"] = platform_match.group(1).strip()

                capabilities_match = re.search(r'Capabilities:\s*(.+)', block)
                if capabilities_match:
                    neighbor["capabilities"] = capabilities_match.group(1).strip()

                if neighbor:
                    neighbors.append(neighbor)

        return json.dumps({
            "device": device_name,
            "protocol": protocol.upper(),
            "total_neighbors": len(neighbors),
            "neighbors": neighbors
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


TOOLS = [
    {"fn": get_routing_table, "name": "get_routing_table", "category": "operations"},
    {"fn": get_neighbors, "name": "get_neighbors", "category": "operations"},
]
