"""
NetworkOps Device Metrics Collectors
v1.1.0

This package contains collectors for gathering metrics from different device types:
- switch_collector: Cisco Cat9kv switches via CLI
- linux_collector: Alpine-1, Docker-1 via SSH
- containerlab_collector: edge1, spine1, server1, server2 via Docker stats
- router_bgp_collector: R1-R4 BGP neighbor count via NETCONF
"""

from .switch_collector import collect_switch_metrics, SWITCHES
from .linux_collector import collect_linux_metrics, LINUX_HOSTS
from .containerlab_collector import collect_containerlab_metrics, CLAB_DEVICES
from .router_bgp_collector import collect_router_bgp_metrics, ROUTERS

__all__ = [
    'collect_switch_metrics',
    'collect_linux_metrics',
    'collect_containerlab_metrics',
    'collect_router_bgp_metrics',
    'SWITCHES',
    'LINUX_HOSTS',
    'CLAB_DEVICES',
    'ROUTERS',
]
