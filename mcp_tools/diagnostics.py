"""
Diagnostics operations: ARP, MAC tables, ping sweep, traceroute.
"""
import asyncio
import json
import re
import time

from config.devices import DEVICES, is_containerlab_device
from core import log_event
from core.containerlab import run_command as run_containerlab_command
from core.scrapli_manager import get_ios_xe_connection, get_linux_connection
from mcp_tools._shared import throttled
from ._ops_helpers import is_cisco_device


async def get_arp_table(device_name: str, vrf: str = None) -> str:
    """
    Get parsed ARP table from a device.

    Args:
        device_name: Device to query
        vrf: Optional VRF name to filter

    Returns:
        JSON with structured ARP entries
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    if device_type == "cisco_xe":
        cmd = f"show ip arp vrf {vrf}" if vrf else "show ip arp"
    elif device_type == "linux":
        cmd = "ip neigh show"
    else:
        return json.dumps({"error": f"ARP table not supported for device type: {device_type}"})

    try:
        if device_type == "cisco_xe":
            async with get_ios_xe_connection(device_name) as conn:
                response = await conn.send_command(cmd)
                output = response.result
        elif device_type == "linux":
            async with get_linux_connection(device_name) as conn:
                response = await conn.send_command(cmd)
                output = response.result

        # Parse ARP entries
        entries = []

        if device_type == "cisco_xe":
            # Format: "Internet  10.0.12.2   1   0050.56bf.1234  ARPA   GigabitEthernet1"
            for line in output.splitlines():
                match = re.match(
                    r'Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+|-)\s+([0-9a-fA-F\.]+)\s+(\w+)\s+(\S+)',
                    line.strip()
                )
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "age_minutes": int(match.group(2)) if match.group(2) != '-' else 0,
                        "mac": match.group(3),
                        "type": match.group(4),
                        "interface": match.group(5)
                    })
        elif device_type == "linux":
            # Format: "10.3.0.1 dev eth0 lladdr 00:50:56:bf:12:34 REACHABLE"
            for line in output.splitlines():
                match = re.match(
                    r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-fA-F:]+)\s+(\w+)',
                    line.strip()
                )
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "interface": match.group(2),
                        "mac": match.group(3),
                        "state": match.group(4)
                    })

        return json.dumps({
            "device": device_name,
            "vrf": vrf,
            "total_entries": len(entries),
            "entries": entries
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


async def get_mac_table(device_name: str, vlan: int = None) -> str:
    """
    Get MAC address table from a switch.

    Args:
        device_name: Switch to query
        vlan: Optional VLAN ID to filter

    Returns:
        JSON with MAC address entries
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "MAC table only supported for IOS-XE devices"})

    cmd = f"show mac address-table vlan {vlan}" if vlan else "show mac address-table"

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(cmd)
            output = response.result

        # Parse MAC table entries
        entries = []
        # Format: "  1    0050.56bf.1234    DYNAMIC     Gi1/0/1"
        for line in output.splitlines():
            match = re.match(
                r'\s*(\d+)\s+([0-9a-fA-F\.]+)\s+(\w+)\s+(\S+)',
                line.strip()
            )
            if match:
                entries.append({
                    "vlan": int(match.group(1)),
                    "mac": match.group(2),
                    "type": match.group(3),
                    "port": match.group(4)
                })

        # Count by VLAN
        vlan_counts = {}
        for entry in entries:
            v = entry["vlan"]
            vlan_counts[v] = vlan_counts.get(v, 0) + 1

        return json.dumps({
            "device": device_name,
            "filter_vlan": vlan,
            "total_entries": len(entries),
            "by_vlan": vlan_counts,
            "entries": entries
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


async def ping_sweep(device_name: str, targets: str, count: int = 2) -> str:
    """
    Ping multiple IP addresses from a device.

    Args:
        device_name: Source device to ping from
        targets: Comma-separated IP addresses (e.g., "10.0.0.1,10.0.0.2,10.0.0.3")
        count: Number of pings per target (default 2)

    Returns:
        JSON with reachability results for each target
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    target_list = [t.strip() for t in targets.split(",")]

    if not target_list:
        return json.dumps({"error": "No targets provided"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    start = time.time()
    results = {}

    async def ping_target(target: str) -> tuple:
        if is_containerlab_device(device_name):
            cmd = f"ping -c {count} -W 2 {target}"
            try:
                output = run_containerlab_command(device_name, cmd)
                if "error" in output.lower() and output.startswith("Error:"):
                    return (target, {"reachable": False, "error": output})
                if "0% packet loss" in output:
                    return (target, {"reachable": True, "success_rate": 100})
                elif "100% packet loss" in output:
                    return (target, {"reachable": False, "success_rate": 0})
                else:
                    match = re.search(r'(\d+)% packet loss', output)
                    if match:
                        loss = int(match.group(1))
                        return (target, {"reachable": loss < 100, "success_rate": 100 - loss})
                return (target, {"reachable": False, "error": "Could not parse result"})
            except Exception as e:
                return (target, {"reachable": False, "error": str(e)})

        elif device_type == "cisco_xe":
            cmd = f"ping {target} repeat {count}"
            try:
                async with get_ios_xe_connection(device_name) as conn:
                    response = await conn.send_command(cmd, timeout_ops=30)
                    output = response.result

                # Parse success rate
                match = re.search(r'Success rate is (\d+) percent', output)
                if match:
                    success_rate = int(match.group(1))
                    return (target, {"reachable": success_rate > 0, "success_rate": success_rate})
                return (target, {"reachable": False, "error": "Could not parse result"})
            except Exception as e:
                return (target, {"reachable": False, "error": str(e)})

        elif device_type == "linux":
            cmd = f"ping -c {count} -W 2 {target}"
            try:
                async with get_linux_connection(device_name) as conn:
                    response = await conn.send_command(cmd)
                    output = response.result

                # Check for success
                if "0% packet loss" in output:
                    return (target, {"reachable": True, "success_rate": 100})
                elif "100% packet loss" in output:
                    return (target, {"reachable": False, "success_rate": 0})
                else:
                    match = re.search(r'(\d+)% packet loss', output)
                    if match:
                        loss = int(match.group(1))
                        return (target, {"reachable": loss < 100, "success_rate": 100 - loss})
                return (target, {"reachable": False, "error": "Could not parse result"})
            except Exception as e:
                return (target, {"reachable": False, "error": str(e)})

        return (target, {"reachable": False, "error": "Unsupported device type"})

    # Run pings in parallel with throttling
    tasks = [throttled(ping_target(target)) for target in target_list]
    ping_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in ping_results:
        if isinstance(result, Exception):
            continue
        target, status = result
        results[target] = status

    elapsed = time.time() - start

    # Summary
    reachable_count = sum(1 for r in results.values() if r.get("reachable"))
    unreachable_count = len(results) - reachable_count

    log_event("ping_sweep", device_name, f"{reachable_count}/{len(target_list)} reachable", "success", "operator")

    return json.dumps({
        "device": device_name,
        "elapsed_seconds": round(elapsed, 2),
        "summary": {
            "total_targets": len(target_list),
            "reachable": reachable_count,
            "unreachable": unreachable_count
        },
        "results": results
    }, indent=2)


async def traceroute(device_name: str, destination: str, source: str = None) -> str:
    """
    Run traceroute from a device to a destination.

    Args:
        device_name: Source device to run traceroute from
        destination: IP address or hostname to trace to
        source: Optional source interface or IP

    Returns:
        JSON with hop-by-hop path analysis
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    # Build command based on device type
    if device_type == "cisco_xe":
        if source:
            cmd = f"traceroute {destination} source {source}"
        else:
            cmd = f"traceroute {destination}"
    elif device_type == "linux":
        cmd = f"traceroute -n -w 2 {destination}"
    else:
        return json.dumps({"error": f"Traceroute not supported for device type: {device_type}"})

    try:
        if device_type == "cisco_xe":
            async with get_ios_xe_connection(device_name) as conn:
                response = await conn.send_command(cmd, timeout_ops=60)
                output = response.result
        elif device_type == "linux":
            async with get_linux_connection(device_name) as conn:
                response = await conn.send_command(cmd)
                output = response.result

        # Parse traceroute output
        hops = []
        for line in output.splitlines():
            # Match hop lines: "  1 10.0.13.2 4 msec 0 msec 0 msec" (Cisco)
            # or: "  1  10.0.13.2  0.234 ms  0.123 ms  0.345 ms" (Linux)
            hop_match = re.match(
                r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+'
                r'(?:(\d+)\s*(?:msec|ms))?',
                line
            )
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_ip = hop_match.group(2)
                rtt = hop_match.group(3)

                hops.append({
                    "hop": hop_num,
                    "ip": hop_ip if hop_ip != '*' else None,
                    "rtt_ms": int(rtt) if rtt else None,
                    "status": "reachable" if hop_ip != '*' else "timeout"
                })

        # Determine final result
        reached_destination = any(
            h.get("ip") == destination for h in hops
        )

        log_event("traceroute", device_name, f"To {destination}: {len(hops)} hops", "success", "operator")

        return json.dumps({
            "device": device_name,
            "destination": destination,
            "source": source,
            "total_hops": len(hops),
            "reached_destination": reached_destination,
            "hops": hops,
            "raw_output": output
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


TOOLS = [
    {"fn": get_arp_table, "name": "get_arp_table", "category": "operations"},
    {"fn": get_mac_table, "name": "get_mac_table", "category": "operations"},
    {"fn": ping_sweep, "name": "ping_sweep", "category": "operations"},
    {"fn": traceroute, "name": "traceroute", "category": "operations"},
]
