"""
Router BGP Metrics Collector
Collects BGP neighbor count from Cisco routers via NETCONF.

Devices: R1, R2, R3, R4 (Cisco C8000V routers)
"""

import asyncio
import logging
from typing import Dict, Any
from ncclient import manager
from defusedxml.ElementTree import fromstring as safe_fromstring

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config.devices import DEVICES, USERNAME, PASSWORD

logger = logging.getLogger(__name__)

# Routers with BGP configured
ROUTERS = ['R1', 'R2', 'R3', 'R4']

# NETCONF namespace for BGP operational data
BGP_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper"


def get_bgp_neighbors_sync(device_name: str) -> Dict[str, Any]:
    """
    Get BGP neighbor count from a router via NETCONF (synchronous).

    Returns:
        Dict with bgp_peers count and neighbor details
    """
    device_info = DEVICES.get(device_name)
    if not device_info:
        return {'bgp_peers': 0, 'error': f'Device {device_name} not found'}

    try:
        with manager.connect(
            host=device_info['host'],
            port=830,
            username=USERNAME,
            password=PASSWORD,
            hostkey_verify=False,
            device_params={'name': 'iosxe'},
            timeout=30
        ) as m:
            # Get BGP neighbor state
            filter_xml = """
            <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <bgp-state-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper">
                    <neighbors>
                        <neighbor>
                            <neighbor-id/>
                            <session-state/>
                        </neighbor>
                    </neighbors>
                </bgp-state-data>
            </filter>
            """

            response = m.get(filter_xml)
            root = safe_fromstring(str(response))

            # Count established neighbors (deduplicate by neighbor ID since
            # NETCONF returns both IPv4 and IPv6 address families)
            established_neighbors = set()
            neighbors = []

            ns = {'bgp': BGP_NS}
            for neighbor in root.findall('.//bgp:neighbor', ns):
                neighbor_id = neighbor.find('bgp:neighbor-id', ns)
                session_state = neighbor.find('bgp:session-state', ns)

                if neighbor_id is not None and session_state is not None:
                    nid = neighbor_id.text
                    state = session_state.text

                    # Only add unique neighbors
                    if nid not in [n['neighbor'] for n in neighbors]:
                        neighbors.append({
                            'neighbor': nid,
                            'state': state
                        })

                    if state == 'fsm-established':
                        established_neighbors.add(nid)

            return {
                'bgp_peers': len(established_neighbors),
                'neighbors': neighbors,
                'up': True
            }

    except Exception as e:
        logger.warning(f"Failed to get BGP neighbors from {device_name}: {e}")
        return {'bgp_peers': 0, 'error': str(e), 'up': True}


async def collect_router_bgp_metrics() -> Dict[str, Dict[str, Any]]:
    """
    Collect BGP metrics from all routers in parallel.

    Returns:
        Dict mapping device name to BGP metrics:
        {
            'R1': {'bgp_peers': 3, 'neighbors': [...], 'up': True},
            'R2': {'bgp_peers': 1, 'neighbors': [...], 'up': True},
            ...
        }
    """
    results = {}

    # Run NETCONF calls in thread pool (ncclient is synchronous)
    loop = asyncio.get_event_loop()

    tasks = []
    for router in ROUTERS:
        task = loop.run_in_executor(None, get_bgp_neighbors_sync, router)
        tasks.append((router, task))

    for router, task in tasks:
        try:
            result = await task
            results[router] = result
        except Exception as e:
            logger.warning(f"BGP collection failed for {router}: {e}")
            results[router] = {'bgp_peers': 0, 'error': str(e), 'up': True}

    return results


# For testing
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(collect_router_bgp_metrics())
    print("Router BGP Metrics:")
    for device, data in results.items():
        print(f"  {device}: {data.get('bgp_peers', 0)} peers - {data}")
