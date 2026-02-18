"""
BGP peer discovery for topology overlay.

Discovers BGP peering relationships by querying devices and adds them
as overlay links in the topology. Works with:
- Cisco IOS-XE (show ip bgp summary)
- FRRouting (show ip bgp summary)
- Nokia SR Linux (show network-instance default protocols bgp neighbor)
"""

import asyncio
import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional
from core.timestamps import isonow

from config.devices import DEVICES, USERNAME, PASSWORD

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class BGPPeer:
    """Standardized BGP peer representation."""
    local_device: str
    peer_ip: str
    peer_device: Optional[str]  # Resolved device name from inventory
    peer_asn: int
    state: str  # Established, Idle, Active, etc.
    prefixes_received: int = 0
    session_type: str = "unknown"  # ibgp or ebgp

    def to_dict(self) -> dict:
        return {
            "local_device": self.local_device,
            "peer_ip": self.peer_ip,
            "peer_device": self.peer_device,
            "peer_asn": self.peer_asn,
            "state": self.state,
            "prefixes_received": self.prefixes_received,
            "session_type": self.session_type,
        }


# =============================================================================
# Dynamic Containerlab IP Resolution
# =============================================================================

_containerlab_ip_cache: dict[str, str] = {}
_containerlab_ip_cache_time: float = 0.0
_CONTAINERLAB_IP_CACHE_TTL = 300  # seconds
_containerlab_ip_refresh_in_progress = False


def _refresh_containerlab_docker_ips():
    """Background refresh of containerlab Docker IPs via a single docker inspect call."""
    global _containerlab_ip_cache, _containerlab_ip_cache_time, _containerlab_ip_refresh_in_progress

    if _containerlab_ip_refresh_in_progress:
        return
    _containerlab_ip_refresh_in_progress = True

    try:
        # Collect all container names and map them back to device names
        container_to_device = {}
        for device_name, device in DEVICES.items():
            if not device.get("device_type", "").startswith("containerlab_"):
                continue
            container = device.get("container")
            if container:
                container_to_device[container] = device_name

        if not container_to_device:
            return

        # Single docker inspect call for all containers
        cmd = [
            "multipass", "exec", "containerlab", "--",
            "docker", "inspect",
            "--format", "{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ] + list(container_to_device.keys())

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        ip_map = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                container_name = parts[0].lstrip("/")
                ip = parts[1]
                device_name = container_to_device.get(container_name)
                if device_name and ip:
                    ip_map[device_name] = ip

        _containerlab_ip_cache = ip_map
        _containerlab_ip_cache_time = time.time()
        logger.debug("Refreshed containerlab Docker IPs: %s", ip_map)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("Failed to refresh containerlab Docker IPs: %s", e)
    finally:
        _containerlab_ip_refresh_in_progress = False


def _get_containerlab_docker_ips() -> dict[str, str]:
    """Get current containerlab device IPs, refreshing in background if stale.

    Returns cached results immediately. If cache is expired, triggers a
    background refresh and returns stale cache (or empty dict on first call).
    """
    now = time.time()
    if (now - _containerlab_ip_cache_time) >= _CONTAINERLAB_IP_CACHE_TTL:
        # Trigger background refresh — don't block the caller
        _threading.Thread(target=_refresh_containerlab_docker_ips, daemon=True).start()

    return _containerlab_ip_cache


# Eagerly start background refresh on module load so cache is warm
import threading as _threading
_threading.Thread(target=_refresh_containerlab_docker_ips, daemon=True).start()


# =============================================================================
# IP to Device Mapping
# =============================================================================

def build_ip_to_device_map() -> dict[str, str]:
    """Build a mapping of IP addresses to device names from inventory."""
    ip_map = {}

    for device_name, device in DEVICES.items():
        # Management IP
        host = device.get("host", "")
        if host:
            ip_map[host] = device_name

        # Also add known loopback IPs from centralized map
        from config.devices import LOOPBACK_MAP
        if device_name in LOOPBACK_MAP:
            ip_map[LOOPBACK_MAP[device_name]] = device_name

    # Add point-to-point link IPs (for BGP peerings using link addresses)
    from config.devices import LINK_IP_MAP
    ip_map.update(LINK_IP_MAP)

    # Add current Docker IPs for containerlab devices (may differ from static config)
    docker_ips = _get_containerlab_docker_ips()
    for device_name, docker_ip in docker_ips.items():
        ip_map[docker_ip] = device_name

    return ip_map


# =============================================================================
# Vendor-Specific Parsers
# =============================================================================

def _parse_cisco_bgp_summary(output: str, local_device: str, ip_map: dict) -> list[BGPPeer]:
    """Parse Cisco IOS-XE 'show ip bgp summary' output."""
    peers = []

    # Get local AS from output
    local_as = None
    as_match = re.search(r'local AS number (\d+)', output)
    if as_match:
        local_as = int(as_match.group(1))

    # Parse neighbor lines
    # Format: Neighbor  V  AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
    in_neighbor_section = False

    for line in output.split('\n'):
        line = line.strip()

        # Skip header lines
        if 'Neighbor' in line and 'AS' in line:
            in_neighbor_section = True
            continue

        if not in_neighbor_section:
            continue

        # Skip empty lines
        if not line:
            continue

        # Parse neighbor line
        parts = line.split()
        if len(parts) >= 9:
            try:
                peer_ip = parts[0]
                # Validate it looks like an IP
                if not re.match(r'\d+\.\d+\.\d+\.\d+', peer_ip):
                    continue

                peer_asn = int(parts[2])
                state_or_pfx = parts[-1]

                # Determine state
                if state_or_pfx.isdigit():
                    state = "Established"
                    prefixes = int(state_or_pfx)
                else:
                    state = state_or_pfx
                    prefixes = 0

                # Determine session type
                session_type = "ibgp" if local_as and peer_asn == local_as else "ebgp"

                # Resolve peer device from IP
                peer_device = ip_map.get(peer_ip)

                peers.append(BGPPeer(
                    local_device=local_device,
                    peer_ip=peer_ip,
                    peer_device=peer_device,
                    peer_asn=peer_asn,
                    state=state,
                    prefixes_received=prefixes,
                    session_type=session_type,
                ))
            except (ValueError, IndexError):
                continue

    return peers


def _parse_frr_bgp_summary(output: str, local_device: str, ip_map: dict) -> list[BGPPeer]:
    """Parse FRRouting 'show ip bgp summary' output.

    FRR 8.x adds PfxSnt and Desc columns after State/PfxRcd:
      Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd  PfxSnt  Desc
    The Cisco parser uses parts[-1] which would hit Desc, so we need
    to find the State/PfxRcd column by header position instead.
    """
    peers = []

    local_as = None
    as_match = re.search(r'local AS number (\d+)', output)
    if as_match:
        local_as = int(as_match.group(1))

    # Find the column index of State/PfxRcd from the header
    state_col_idx = None
    in_neighbor_section = False

    for line in output.split('\n'):
        line_stripped = line.strip()

        if 'Neighbor' in line_stripped and 'AS' in line_stripped:
            # Find State/PfxRcd column position
            parts = line_stripped.split()
            for i, col in enumerate(parts):
                if 'State' in col or 'PfxRcd' in col:
                    state_col_idx = i
                    break
            in_neighbor_section = True
            continue

        if not in_neighbor_section or not line_stripped:
            continue

        parts = line_stripped.split()
        if len(parts) >= 9:
            try:
                peer_ip = parts[0]
                if not re.match(r'\d+\.\d+\.\d+\.\d+', peer_ip):
                    continue

                peer_asn = int(parts[2])

                # Use detected column index, fall back to last column
                idx = state_col_idx if state_col_idx and state_col_idx < len(parts) else -1
                state_or_pfx = parts[idx]

                if state_or_pfx.isdigit():
                    state = "Established"
                    prefixes = int(state_or_pfx)
                else:
                    state = state_or_pfx
                    prefixes = 0

                session_type = "ibgp" if local_as and peer_asn == local_as else "ebgp"
                peer_device = ip_map.get(peer_ip)

                peers.append(BGPPeer(
                    local_device=local_device,
                    peer_ip=peer_ip,
                    peer_device=peer_device,
                    peer_asn=peer_asn,
                    state=state,
                    prefixes_received=prefixes,
                    session_type=session_type,
                ))
            except (ValueError, IndexError):
                continue

    return peers


def _parse_nokia_bgp_neighbors(output: str, local_device: str, ip_map: dict) -> list[BGPPeer]:
    """Parse Nokia SR Linux BGP neighbor output."""
    peers = []

    # Try JSON format first
    try:
        data = json.loads(output)
        # Navigate Nokia JSON structure
        for neighbor_ip, neighbor_data in data.get("neighbor", {}).items():
            peer_asn = neighbor_data.get("peer-as", 0)
            state = neighbor_data.get("session-state", "unknown")
            prefixes = neighbor_data.get("received-routes", 0)
            local_as = neighbor_data.get("local-as", 0)

            session_type = "ibgp" if peer_asn == local_as else "ebgp"
            peer_device = ip_map.get(neighbor_ip)

            peers.append(BGPPeer(
                local_device=local_device,
                peer_ip=neighbor_ip,
                peer_device=peer_device,
                peer_asn=peer_asn,
                state=state,
                prefixes_received=prefixes,
                session_type=session_type,
            ))
        return peers
    except (json.JSONDecodeError, AttributeError):
        pass

    # CLI table format fallback
    for line in output.split('\n'):
        if re.match(r'\d+\.\d+\.\d+\.\d+', line.strip()):
            parts = line.split()
            if len(parts) >= 2:
                peer_ip = parts[0]
                peer_device = ip_map.get(peer_ip)
                peers.append(BGPPeer(
                    local_device=local_device,
                    peer_ip=peer_ip,
                    peer_device=peer_device,
                    peer_asn=0,
                    state="unknown",
                    session_type="unknown",
                ))

    return peers


# =============================================================================
# BGP Commands by Device Type
# =============================================================================

BGP_COMMANDS = {
    "cisco_xe": "show ip bgp summary",
    "containerlab_frr": "show ip bgp summary",
    "containerlab_srlinux": "show network-instance default protocols bgp neighbor",
}


# =============================================================================
# Discovery Functions
# =============================================================================

async def _get_bgp_output(device_name: str, device: dict) -> tuple[str, str]:
    """Get BGP summary output from device.

    Returns:
        Tuple of (output, device_type)
    """
    device_type = device.get("device_type", "")

    bgp_command = BGP_COMMANDS.get(device_type)
    if not bgp_command:
        raise ValueError(f"BGP not supported for device type: {device_type}")

    # Use Scrapli for Cisco IOS-XE
    if device_type == "cisco_xe":
        from core.scrapli_manager import get_ios_xe_connection
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(bgp_command)
            return response.result, device_type

    # For containerlab devices
    if device_type.startswith("containerlab_"):
        from core.containerlab import get_containerlab_command_output
        output = await get_containerlab_command_output(device_name, bgp_command)
        return output, device_type

    raise ValueError(f"No connection method for device type: {device_type}")


async def discover_bgp_peers(device_name: str) -> list[BGPPeer]:
    """Discover BGP peers on a single device.

    Args:
        device_name: Name of the device from inventory

    Returns:
        List of BGPPeer objects
    """
    if device_name not in DEVICES:
        return []

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    if device_type not in BGP_COMMANDS:
        return []

    ip_map = build_ip_to_device_map()

    try:
        output, dtype = await _get_bgp_output(device_name, device)

        if dtype == "cisco_xe":
            return _parse_cisco_bgp_summary(output, device_name, ip_map)
        elif dtype == "containerlab_frr":
            return _parse_frr_bgp_summary(output, device_name, ip_map)
        elif dtype == "containerlab_srlinux":
            return _parse_nokia_bgp_neighbors(output, device_name, ip_map)

        return []
    except Exception as e:
        # Log but don't fail - BGP discovery is supplementary
        return []


async def discover_all_bgp_peers(max_concurrent: int = 5) -> dict:
    """Discover BGP peers across all devices.

    Args:
        max_concurrent: Maximum concurrent connections

    Returns:
        Dict with peers list and summary
    """
    import time
    start = time.time()

    # Only query devices that support BGP
    bgp_devices = [
        name for name, dev in DEVICES.items()
        if dev.get("device_type") in BGP_COMMANDS
    ]

    # Limit concurrency
    semaphore = asyncio.Semaphore(max_concurrent)

    async def discover_with_limit(device_name: str) -> list[BGPPeer]:
        async with semaphore:
            return await discover_bgp_peers(device_name)

    # Run discovery on all BGP-capable devices
    tasks = [discover_with_limit(name) for name in bgp_devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Flatten results
    all_peers = []
    for result in results:
        if isinstance(result, list):
            all_peers.extend(result)

    elapsed = time.time() - start

    return {
        "peers": [p.to_dict() for p in all_peers],
        "devices_queried": len(bgp_devices),
        "total_peers": len(all_peers),
        "established": sum(1 for p in all_peers if p.state == "Established"),
        "elapsed_seconds": round(elapsed, 2),
        "timestamp": isonow(),
    }


def bgp_peers_to_links(peers: list[BGPPeer]) -> list[dict]:
    """Convert BGP peers to topology links.

    Only creates links where both ends can be resolved to device names.
    Deduplicates bidirectional peerings (A->B and B->A become one link).

    Args:
        peers: List of BGPPeer objects

    Returns:
        List of link dicts with source, target, and link_type
    """
    links = []
    seen = set()

    for peer in peers:
        # Skip if peer device couldn't be resolved
        if not peer.peer_device:
            continue

        # Skip if not established (optional - could include all)
        if peer.state != "Established":
            continue

        # Create sorted key to deduplicate bidirectional peerings
        link_key = tuple(sorted([peer.local_device, peer.peer_device]))

        if link_key not in seen:
            seen.add(link_key)
            links.append({
                "source": peer.local_device,
                "target": peer.peer_device,
                "source_intf": f"BGP ({peer.session_type})",
                "target_intf": f"AS {peer.peer_asn}",
                "link_type": "bgp",
                "session_type": peer.session_type,
            })

    return links
