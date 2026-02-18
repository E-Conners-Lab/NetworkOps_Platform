"""
Switch Metrics Collector
Collects CPU, memory, and status from Cisco Cat9kv switches via CLI.

Devices: Switch-R1, Switch-R2, Switch-R4
"""

import asyncio
import re
import logging
from typing import Dict, Any, Optional

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config.devices import DEVICES, USERNAME, PASSWORD

logger = logging.getLogger(__name__)

# Switches to collect metrics from
SWITCHES = ['Switch-R1', 'Switch-R2', 'Switch-R4']


def parse_cpu_output(output: str) -> float:
    """
    Parse CPU utilization from 'show processes cpu' output.
    Example: CPU utilization for five seconds: 5%/0%; one minute: 6%; five minutes: 5%
    """
    try:
        # Look for "five seconds: X%" pattern
        match = re.search(r'five seconds:\s*(\d+)%', output)
        if match:
            return float(match.group(1))

        # Alternative format
        match = re.search(r'CPU utilization.*?(\d+)%', output)
        if match:
            return float(match.group(1))
    except Exception as e:
        logger.warning(f"Failed to parse CPU output: {e}")

    return 0.0


def parse_memory_output(output: str) -> float:
    """
    Parse memory utilization from 'show memory statistics' output.
    Returns percentage used.
    """
    try:
        # Look for Processor pool line
        for line in output.splitlines():
            if 'Processor' in line and 'lsmpi' not in line.lower():
                # Format: Processor   Total(b)    Used(b)    Free(b)
                parts = line.split()
                if len(parts) >= 4:
                    total = int(parts[1])
                    used = int(parts[2])
                    if total > 0:
                        return (used / total) * 100
    except Exception as e:
        logger.warning(f"Failed to parse memory output: {e}")

    return 0.0


async def collect_single_switch_metrics(switch_name: str) -> Dict[str, Any]:
    """Collect metrics from a single switch using Netmiko."""
    try:
        from netmiko import ConnectHandler

        device_info = DEVICES.get(switch_name)
        if not device_info:
            return {'up': False, 'error': f'Device {switch_name} not found in inventory'}

        # Connect to switch
        device = {
            'device_type': 'cisco_xe',
            'host': device_info['host'],
            'username': USERNAME,
            'password': PASSWORD,
            'timeout': 30,
        }

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()

        def connect_and_collect():
            with ConnectHandler(**device) as conn:
                cpu_output = conn.send_command('show processes cpu | include CPU')
                mem_output = conn.send_command('show memory statistics | include Processor')
                return cpu_output, mem_output

        cpu_output, mem_output = await loop.run_in_executor(None, connect_and_collect)

        return {
            'cpu': parse_cpu_output(cpu_output),
            'memory': parse_memory_output(mem_output),
            'up': True,
        }

    except Exception as e:
        logger.error(f"Failed to collect metrics from {switch_name}: {e}")
        return {
            'up': False,
            'error': str(e),
            'cpu': 0,
            'memory': 0,
        }


async def collect_switch_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Collect metrics from all switches in parallel.

    Returns:
        Dict mapping switch name to metrics:
        {
            'Switch-R1': {'cpu': 5.0, 'memory': 45.2, 'up': True},
            'Switch-R2': {'cpu': 3.0, 'memory': 42.1, 'up': True},
            'Switch-R4': {'up': False, 'error': 'Connection refused'},
        }
    """
    tasks = [collect_single_switch_metrics(switch) for switch in SWITCHES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    metrics = {}
    for switch, result in zip(SWITCHES, results):
        if isinstance(result, Exception):
            metrics[switch] = {'up': False, 'error': str(result)}
        else:
            metrics[switch] = result

    return metrics


# For testing
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(collect_switch_metrics())
    print("Switch Metrics:")
    for switch, data in results.items():
        print(f"  {switch}: {data}")
