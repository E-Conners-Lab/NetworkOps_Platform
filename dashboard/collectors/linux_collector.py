"""
Linux Host Metrics Collector
Collects CPU, memory, and disk usage from Linux hosts via SSH.

Devices: Alpine-1, Docker-1
"""

import asyncio
import re
import logging
from typing import Dict, Any

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config.devices import DEVICES, USERNAME, PASSWORD

logger = logging.getLogger(__name__)

# Linux hosts to collect metrics from
LINUX_HOSTS = ['Alpine-1', 'Docker-1']


def parse_memory_info(output: str) -> Dict[str, float]:
    """
    Parse memory info from 'free -m' or 'cat /proc/meminfo'.
    Returns dict with used, total, and percent.
    """
    try:
        # Try parsing 'free' output first
        # Mem:          1989        845        143         16        1000        987
        for line in output.splitlines():
            if line.startswith('Mem:'):
                parts = line.split()
                if len(parts) >= 3:
                    total = float(parts[1])
                    used = float(parts[2])
                    if total > 0:
                        return {
                            'total': total,
                            'used': used,
                            'percent': (used / total) * 100
                        }
    except Exception as e:
        logger.warning(f"Failed to parse memory output: {e}")

    return {'total': 0, 'used': 0, 'percent': 0}


def parse_disk_info(output: str) -> float:
    """
    Parse disk usage from 'df -h /' output.
    Returns percentage used.
    """
    try:
        for line in output.splitlines():
            if '/' in line and '%' in line:
                # Find the percentage (e.g., "45%")
                match = re.search(r'(\d+)%', line)
                if match:
                    return float(match.group(1))
    except Exception as e:
        logger.warning(f"Failed to parse disk output: {e}")

    return 0.0


def parse_cpu_info(output: str) -> float:
    """
    Parse CPU usage from 'top' or 'uptime' output.
    Uses load average as a proxy for CPU usage.
    """
    try:
        # Parse uptime output: load average: 0.00, 0.01, 0.05
        match = re.search(r'load average[s]?:\s*([\d.]+)', output)
        if match:
            load = float(match.group(1))
            # Convert 1-minute load average to rough percentage
            # Assuming single core, load of 1.0 = 100%
            return min(load * 100, 100.0)
    except Exception as e:
        logger.warning(f"Failed to parse CPU output: {e}")

    return 0.0


async def collect_single_linux_metrics(host_name: str) -> Dict[str, Any]:
    """Collect metrics from a single Linux host using Netmiko."""
    try:
        from netmiko import ConnectHandler

        device_info = DEVICES.get(host_name)
        if not device_info:
            return {'up': False, 'error': f'Device {host_name} not found in inventory'}

        # Connect to Linux host
        device = {
            'device_type': 'linux',
            'host': device_info['host'],
            'username': USERNAME,
            'password': PASSWORD,
            'timeout': 30,
        }

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()

        def connect_and_collect():
            with ConnectHandler(**device) as conn:
                # Get memory info
                mem_output = conn.send_command('free -m')

                # Get disk info
                disk_output = conn.send_command('df -h /')

                # Get CPU/load info
                cpu_output = conn.send_command('uptime')

                return mem_output, disk_output, cpu_output

        mem_output, disk_output, cpu_output = await loop.run_in_executor(
            None, connect_and_collect
        )

        mem_info = parse_memory_info(mem_output)
        disk_percent = parse_disk_info(disk_output)
        cpu_percent = parse_cpu_info(cpu_output)

        return {
            'cpu': cpu_percent,
            'memory': mem_info['percent'],
            'disk': disk_percent,
            'up': True,
        }

    except Exception as e:
        logger.error(f"Failed to collect metrics from {host_name}: {e}")
        return {
            'up': False,
            'error': str(e),
            'cpu': 0,
            'memory': 0,
            'disk': 0,
        }


async def collect_linux_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Collect metrics from all Linux hosts in parallel.

    Returns:
        Dict mapping host name to metrics:
        {
            'Alpine-1': {'cpu': 5.0, 'memory': 45.2, 'disk': 32.0, 'up': True},
            'Docker-1': {'cpu': 12.0, 'memory': 68.5, 'disk': 55.0, 'up': True},
        }
    """
    tasks = [collect_single_linux_metrics(host) for host in LINUX_HOSTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    metrics = {}
    for host, result in zip(LINUX_HOSTS, results):
        if isinstance(result, Exception):
            metrics[host] = {'up': False, 'error': str(result)}
        else:
            metrics[host] = result

    return metrics


# For testing
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(collect_linux_metrics())
    print("Linux Host Metrics:")
    for host, data in results.items():
        print(f"  {host}: {data}")
