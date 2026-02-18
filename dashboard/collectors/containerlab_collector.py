"""
Containerlab Metrics Collector
Collects CPU, memory, and BGP status from Containerlab devices via Docker.

Devices: edge1 (FRRouting), spine1 (Nokia SR Linux), server1, server2 (Alpine)
"""

import asyncio
import re
import logging
import os
from typing import Dict, Any, Optional

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logger = logging.getLogger(__name__)

# Build containerlab device configuration from centralized inventory
from config.devices import DEVICES

_CLAB_TYPE_MAP = {
    'containerlab_frr': 'frrouting',
    'containerlab_srlinux': 'nokia',
    'containerlab_linux': 'alpine',
}

CLAB_DEVICES = {
    name: {
        'container': d.get('container', f'clab-datacenter-{name}'),
        'type': _CLAB_TYPE_MAP.get(d.get('device_type', ''), 'unknown'),
    }
    for name, d in DEVICES.items()
    if d.get('device_type', '').startswith('containerlab_')
}

# Multipass VM name for containerlab
CONTAINERLAB_VM = os.getenv('CONTAINERLAB_VM', 'containerlab')


async def run_multipass_command(command: str, timeout: int = 30) -> str:
    """Run a command inside the Multipass VM."""
    try:
        full_command = f"multipass exec {CONTAINERLAB_VM} -- {command}"
        process = await asyncio.create_subprocess_shell(
            full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )

        if process.returncode != 0:
            logger.warning(f"Command failed: {stderr.decode()}")
            return ""

        return stdout.decode()

    except asyncio.TimeoutError:
        logger.error(f"Command timed out: {command}")
        return ""
    except Exception as e:
        logger.error(f"Failed to run multipass command: {e}")
        return ""


async def get_docker_stats() -> Dict[str, Dict[str, float]]:
    """
    Get CPU and memory stats for all containers via docker stats.

    Returns:
        Dict mapping container name to stats:
        {'clab-datacenter-edge1': {'cpu': 5.2, 'memory': 12.5}, ...}
    """
    stats = {}

    # Get docker stats in one shot
    output = await run_multipass_command(
        'sudo docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}"'
    )

    if not output:
        return stats

    for line in output.strip().splitlines():
        try:
            parts = line.split('|')
            if len(parts) >= 3:
                name = parts[0].strip()
                cpu = float(parts[1].replace('%', '').strip())
                mem = float(parts[2].replace('%', '').strip())
                stats[name] = {'cpu': cpu, 'memory': mem}
        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse docker stats line: {line} - {e}")

    return stats


async def get_bgp_peer_count(container: str) -> int:
    """Get the number of established BGP peers for a FRRouting container."""
    try:
        output = await run_multipass_command(
            f'sudo docker exec {container} vtysh -c "show ip bgp summary"'
        )

        if not output:
            return 0

        # Count established BGP peers
        # FRRouting format: when established, State/PfxRcd shows a number (prefixes received)
        # When not established, it shows: Idle, Connect, Active, OpenSent, OpenConfirm
        established_count = 0
        in_neighbor_section = False

        for line in output.splitlines():
            # Skip header lines, look for neighbor entries
            if 'Neighbor' in line and 'State' in line:
                in_neighbor_section = True
                continue

            if in_neighbor_section and line.strip():
                # Neighbor lines start with an IP address
                parts = line.split()
                if len(parts) >= 10:
                    # Check if first part looks like an IP
                    first_part = parts[0]
                    if '.' in first_part or ':' in first_part:
                        # State/PfxRcd is typically the 10th column (index 9)
                        # If it's a number, the peer is established
                        state = parts[9] if len(parts) > 9 else parts[-2]
                        try:
                            int(state)  # If it parses as int, it's established
                            established_count += 1
                        except ValueError:
                            pass  # Not established (Idle, Active, Connect, etc.)

        return established_count

    except Exception as e:
        logger.warning(f"Failed to get BGP peers for {container}: {e}")
        return 0


async def check_container_running(container: str) -> bool:
    """Check if a container is running."""
    output = await run_multipass_command(
        f'sudo docker inspect -f "{{{{.State.Running}}}}" {container}'
    )
    return output.strip().lower() == 'true'


async def collect_containerlab_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Collect metrics from all Containerlab devices.

    Returns:
        Dict mapping device name to metrics:
        {
            'edge1': {'cpu': 5.0, 'memory': 12.5, 'bgp_peers': 2, 'up': True},
            'spine1': {'cpu': 3.0, 'memory': 8.2, 'up': True},
            'server1': {'cpu': 0.5, 'memory': 2.1, 'up': True},
            'server2': {'up': False, 'error': 'Container not running'},
        }
    """
    metrics = {}

    try:
        # Get docker stats for all containers at once
        docker_stats = await get_docker_stats()

        # Process each device
        for device_name, device_info in CLAB_DEVICES.items():
            container = device_info['container']
            device_type = device_info['type']

            # Check if we got stats for this container
            container_stats = None
            for stats_name, stats in docker_stats.items():
                if container in stats_name:
                    container_stats = stats
                    break

            if container_stats:
                device_metrics = {
                    'cpu': container_stats['cpu'],
                    'memory': container_stats['memory'],
                    'up': True,
                }

                # Get BGP peers for FRRouting devices
                if device_type == 'frrouting':
                    bgp_peers = await get_bgp_peer_count(container)
                    device_metrics['bgp_peers'] = bgp_peers

                metrics[device_name] = device_metrics
            else:
                # Container not found in stats - check if it's running
                is_running = await check_container_running(container)
                if is_running:
                    metrics[device_name] = {
                        'cpu': 0,
                        'memory': 0,
                        'up': True,
                    }
                else:
                    metrics[device_name] = {
                        'up': False,
                        'error': 'Container not running',
                    }

    except Exception as e:
        logger.error(f"Failed to collect containerlab metrics: {e}")
        # Return all devices as down
        for device_name in CLAB_DEVICES:
            metrics[device_name] = {'up': False, 'error': str(e)}

    return metrics


# For testing
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(collect_containerlab_metrics())
    print("Containerlab Metrics:")
    for device, data in results.items():
        print(f"  {device}: {data}")
