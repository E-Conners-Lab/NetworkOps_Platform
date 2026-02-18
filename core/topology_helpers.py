"""
Topology discovery business logic.

Extracted from api_server.py lines 751-1136.
Contains helper functions for topology discovery, device health checks,
and cache invalidation.
"""

import logging
import subprocess
import time
import xml.etree.ElementTree as ET

from netmiko import ConnectHandler

from config.devices import DEVICES, CONTAINERLAB_LINKS, is_containerlab_device
from core.containerlab import check_health_status as check_containerlab_health
from core.netconf_client import get_netconf_connection

logger = logging.getLogger(__name__)

# Linux hosts topology metadata (derived from device inventory)
LINUX_HOSTS = {
    name: {
        "connected_to": d["connected_to"],
        "local_intf": d["local_intf"],
        "remote_intf": d["remote_intf"],
        "ip": d.get("lan_ip", ""),
    }
    for name, d in DEVICES.items()
    if d.get("device_type") == "linux" and d.get("connected_to")
}

# Containerlab device metadata (derived from device inventory)
CONTAINERLAB_HOSTS = {
    name: {"platform": d.get("platform", ""), "loopback": d.get("loopback", "")}
    for name, d in DEVICES.items()
    if d.get("device_type", "").startswith("containerlab_")
}

# Cache for discovered active interfaces
_active_interfaces_cache = {}
_active_interfaces_cache_time = {}
ACTIVE_INTERFACES_CACHE_TTL = 300  # 5 minutes


def get_active_interfaces(device_name: str) -> list[str]:
    """
    Dynamically discover active (admin-up, non-management) interfaces for a device.

    Returns list of interface names like ['GigabitEthernet1', 'GigabitEthernet2'].
    Uses caching to avoid repeated NETCONF calls.
    """
    cache_time = _active_interfaces_cache_time.get(device_name, 0)
    if time.time() - cache_time < ACTIVE_INTERFACES_CACHE_TTL:
        cached = _active_interfaces_cache.get(device_name)
        if cached is not None:
            return cached

    active = []

    try:
        with get_netconf_connection(device_name, timeout=10) as m:
            filter_xml = """
                <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
                    <interface>
                        <name/>
                        <enabled/>
                    </interface>
                </interfaces>
            """
            result = m.get_config(source='running', filter=('subtree', filter_xml))
            root = ET.fromstring(str(result))  # nosec B314 — trusted NETCONF device response
            ns = {'if': 'urn:ietf:params:xml:ns:yang:ietf-interfaces'}

            for intf in root.findall('.//if:interface', ns):
                name_elem = intf.find('if:name', ns)
                enabled_elem = intf.find('if:enabled', ns)

                if name_elem is None:
                    continue

                name = name_elem.text
                if not name.startswith('GigabitEthernet'):
                    continue
                if name in ['GigabitEthernet4', 'GigabitEthernet0/0']:
                    continue

                enabled = True
                if enabled_elem is not None:
                    enabled = enabled_elem.text.lower() == 'true'

                if enabled:
                    active.append(name)

    except Exception:
        pass

    _active_interfaces_cache[device_name] = active
    _active_interfaces_cache_time[device_name] = time.time()

    return active


def check_device_health(device, device_name=None, telemetry_data=None):
    """Check the health status of a device.

    Args:
        device: Device dict from DEVICES
        device_name: Device name string
        telemetry_data: Optional telemetry store for interface state checks

    Returns:
        "healthy", "degraded", or "critical"
    """
    device_type = device.get('device_type', '')

    if device_type.startswith('containerlab_'):
        if device_name:
            return check_containerlab_health(device_name)
        return "critical"

    if device_type == 'linux':
        try:
            connection = ConnectHandler(**device)
            connection.send_command("hostname", read_timeout=5)
            connection.disconnect()
            return "healthy"
        except Exception:
            return "critical"

    # Cisco IOS-XE devices
    if device_name:
        try:
            with get_netconf_connection(device_name, timeout=5) as m:
                pass

            if telemetry_data is not None:
                try:
                    interface_states = telemetry_data.get_interface_states()
                    if device_name in interface_states:
                        device_states = interface_states[device_name]
                        interfaces_to_check = get_active_interfaces(device_name)
                        for intf in interfaces_to_check:
                            if intf in device_states:
                                if device_states[intf].get('state') == 'down':
                                    return "degraded"
                except Exception:
                    pass

            return "healthy"
        except Exception:
            return "critical"

    return "critical"


def is_valid_link(device1, device2):
    """Check if a link between two devices is valid topology."""
    names = sorted([device1, device2])

    if names[0].startswith('R') and names[1].startswith('R'):
        return True

    if 'Switch' in names[1]:
        switch_name = names[1]
        router_name = names[0]
        expected_router = switch_name.replace('Switch-', '')
        return router_name == expected_router

    return False


def _discover_topology_demo():
    """Return instant topology from demo fixtures (no SSH)."""
    from core.demo.fixtures import DEMO_DEVICES, DEMO_TOPOLOGY_LINKS, DEMO_BGP_PEERS

    platform_map = {
        "cisco_xe": "C8000V",
        "linux": "Linux",
        "containerlab_frr": "FRRouting",
    }

    nodes = []
    for name, dev in DEMO_DEVICES.items():
        dtype = dev.get("device_type", "")
        if dtype == "cisco_xe" and name.startswith("Switch"):
            platform = "Cat9kv"
        else:
            platform = platform_map.get(dtype, dtype)
        nodes.append({
            "id": name,
            "ip": dev["host"],
            "status": "healthy",
            "platform": platform,
        })

    links = [
        {**link, "link_type": "lldp"} for link in DEMO_TOPOLOGY_LINKS
    ]

    # Build reverse lookup: loopback IP -> device name
    ip_to_device = {}
    for name, dev in DEMO_DEVICES.items():
        if "loopback" in dev:
            ip_to_device[dev["loopback"]] = name

    bgp_links = []
    seen_bgp = set()
    for device, peers in DEMO_BGP_PEERS.items():
        for peer in peers:
            peer_ip = peer.get("neighbor", "")
            target = ip_to_device.get(peer_ip, peer_ip)
            # Deduplicate bidirectional peers (R1->R2 and R2->R1)
            link_key = tuple(sorted([device, target]))
            if link_key in seen_bgp:
                continue
            seen_bgp.add(link_key)
            bgp_links.append({
                "source": device,
                "target": target,
                "peer_ip": peer_ip,
                "remote_as": peer.get("remote_as", 0),
                "state": peer.get("state", "Unknown"),
                "link_type": "bgp",
            })

    return {
        "nodes": nodes,
        "links": links,
        "bgp_links": bgp_links,
        "_protocol": "demo",
        "_link_counts": {
            "lldp": 0,
            "static": len(links),
            "bgp": len(bgp_links),
            "total": len(links),
        },
    }


def discover_topology(telemetry_data=None):
    """
    Discover network topology using LLDP + BGP overlay.

    Args:
        telemetry_data: Optional telemetry store for health checks

    Returns:
        Dict with nodes, links, bgp_links, and metadata
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        return _discover_topology_demo()

    import asyncio
    from core.lldp import discover_lldp_topology
    from core.bgp_discovery import discover_all_bgp_peers, bgp_peers_to_links, BGPPeer

    bgp_links = []

    async def discover_all():
        lldp_task = discover_lldp_topology()
        bgp_task = discover_all_bgp_peers()
        return await asyncio.gather(lldp_task, bgp_task, return_exceptions=True)

    try:
        try:
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, discover_all())
                results = future.result(timeout=60)
        except RuntimeError:
            results = asyncio.run(discover_all())

        lldp_result = results[0] if not isinstance(results[0], Exception) else None
        bgp_result = results[1] if not isinstance(results[1], Exception) else None

        if lldp_result:
            nodes = {node["id"]: node for node in lldp_result["topology"]["nodes"]}
        else:
            nodes = {}

        links = []
        seen_links = set()

        if lldp_result:
            for link in lldp_result["topology"]["links"]:
                link_key = tuple(sorted([link["source"], link["target"]]))
                if link_key not in seen_links and is_valid_link(link["source"], link["target"]):
                    seen_links.add(link_key)
                    links.append({
                        "source": link["source"],
                        "target": link["target"],
                        "source_intf": link.get("source_interface", "unknown"),
                        "target_intf": link.get("target_interface", "unknown"),
                        "link_type": "lldp"
                    })

        if bgp_result and bgp_result.get("peers"):
            peers = [
                BGPPeer(
                    local_device=p["local_device"],
                    peer_ip=p["peer_ip"],
                    peer_device=p["peer_device"],
                    peer_asn=p["peer_asn"],
                    state=p["state"],
                    prefixes_received=p.get("prefixes_received", 0),
                    session_type=p.get("session_type", "unknown"),
                )
                for p in bgp_result["peers"]
            ]
            bgp_links = bgp_peers_to_links(peers)

    except Exception as e:
        logger.warning(f"LLDP discovery failed, using inventory only: {e}")
        nodes = {}
        links = []
        seen_links = set()

        for device_name, device in DEVICES.items():
            device_type = device.get('device_type', '')
            status = check_device_health(device, device_name, telemetry_data)

            platform_map = {
                'linux': "Linux",
                'containerlab_srlinux': "Nokia SR Linux",
                'containerlab_frr': "FRRouting",
                'containerlab_linux': "Alpine (clab)",
                'juniper_junos': "Juniper Junos",
                'aruba_aoscx': "HPE Aruba CX",
                'hp_procurve': "HPE ProCurve",
                'hp_comware': "HPE Comware",
            }
            platform = platform_map.get(device_type)
            if platform is None:
                if device_type == 'cisco_xe':
                    platform = "Cat9kv" if device_name.startswith("Switch") else "C8000V"
                elif device_name.startswith("R"):
                    platform = "C8000V"
                elif device_name.startswith("Switch"):
                    platform = "Cat9kv"
                else:
                    platform = "unknown"

            nodes[device_name] = {
                "id": device_name,
                "ip": device['host'],
                "status": status,
                "platform": platform
            }

    # Add static Linux host links
    for host_name, host_info in LINUX_HOSTS.items():
        if host_name in nodes:
            link_key = tuple(sorted([host_name, host_info["connected_to"]]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                links.append({
                    "source": host_name,
                    "target": host_info["connected_to"],
                    "source_intf": host_info["local_intf"],
                    "target_intf": host_info["remote_intf"],
                    "link_type": "static"
                })

    # Add static Containerlab links
    for link in CONTAINERLAB_LINKS:
        source = link["source"]
        target = link["target"]
        if source in nodes and target in nodes:
            link_key = tuple(sorted([source, target]))
            if link_key not in seen_links:
                seen_links.add(link_key)
                links.append({
                    "source": source,
                    "target": target,
                    "source_intf": link["source_intf"],
                    "target_intf": link["target_intf"],
                    "link_type": "static"
                })

    lldp_count = sum(1 for l in links if l.get("link_type") == "lldp")
    static_count = sum(1 for l in links if l.get("link_type") == "static")

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "bgp_links": bgp_links,
        "_protocol": "lldp",
        "_link_counts": {
            "lldp": lldp_count,
            "static": static_count,
            "bgp": len(bgp_links),
            "total": len(links)
        }
    }


def is_config_command(command: str) -> bool:
    """Check if a command might change device configuration."""
    command_lower = command.lower().strip()

    if command_lower.startswith('show '):
        return False

    config_indicators = [
        'configure', 'config', 'conf t',
        'interface ', 'router ', 'ip route',
        'no ', 'set ', 'delete ',
        'shutdown', 'no shutdown',
        'vlan ', 'switchport',
    ]
    return any(indicator in command_lower for indicator in config_indicators)


def invalidate_device_cache(device_name: str, is_config: bool = False):
    """Invalidate cached data for a device after changes."""
    from core import log_event

    try:
        from dashboard.extensions import cache
        cache.clear()
        log_event('cache_invalidate', device_name, f'Cache invalidated (config={is_config})', 'success', 'system')
    except Exception as e:
        log_event('cache_invalidate', device_name, f'Cache invalidation failed: {e}', 'warning', 'system')
