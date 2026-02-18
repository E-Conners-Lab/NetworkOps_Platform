"""
NETCONF MCP tools.

This module provides tools for NETCONF operations:
- get_interfaces_netconf: Get interface info via NETCONF
- get_netconf_capabilities: Get NETCONF capabilities
- get_bgp_neighbors_netconf: Get BGP neighbors via NETCONF
"""

import asyncio
import json
import xml.etree.ElementTree as ET

from config.devices import DEVICES
from core.netconf_client import get_netconf_connection


# =============================================================================
# Helper Functions
# =============================================================================

def is_cisco_device(device_name: str) -> bool:
    """Check if device is a Cisco IOS-XE device."""
    device = DEVICES.get(device_name, {})
    return device.get("device_type") == "cisco_xe"


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def get_interfaces_netconf(device_name: str) -> str:
    """Get interface information via NETCONF"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "NETCONF only supported for IOS-XE devices"})

    def _get_interfaces():
        try:
            with get_netconf_connection(device_name) as m:
                intf_filter = """<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>"""
                response = m.get(filter=("subtree", intf_filter))

                root = ET.fromstring(response.xml)  # nosec B314 — trusted NETCONF device response
                ns = {
                    'ietf-if': 'urn:ietf:params:xml:ns:yang:ietf-interfaces',
                    'ietf-ip': 'urn:ietf:params:xml:ns:yang:ietf-ip'
                }

                interfaces = root.findall('.//ietf-if:interface', ns)

                results = []
                for intf in interfaces:
                    name = intf.find('ietf-if:name', ns).text
                    enabled = intf.find('ietf-if:enabled', ns).text

                    ip_elem = intf.find('.//ietf-ip:ip', ns)
                    ip = ip_elem.text if ip_elem is not None else 'No IP'

                    mask_elem = intf.find('.//ietf-ip:netmask', ns)
                    mask = mask_elem.text if mask_elem is not None else ''

                    results.append({
                        "name": name,
                        "ip": ip,
                        "netmask": mask,
                        "enabled": enabled == "true"
                    })

                return {"device": device_name, "interfaces": results}

        except Exception as e:
            return {"error": "NETCONF connection failed", "device": device_name, "details": str(e)}

    result = await asyncio.to_thread(_get_interfaces)
    return json.dumps(result, indent=2)


async def get_netconf_capabilities(device_name: str, search_filter: str = "") -> str:
    """Get NETCONF capabilities for a device. Optionally filter by keyword (e.g., 'ospf', 'bgp')"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "NETCONF only supported for IOS-XE devices"})

    def _get_capabilities():
        try:
            with get_netconf_connection(device_name) as m:
                capabilities = list(m.server_capabilities)

                if search_filter:
                    capabilities = [cap for cap in capabilities if search_filter.lower() in cap.lower()]

                return {
                    "device": device_name,
                    "filter": search_filter if search_filter else "none",
                    "count": len(capabilities),
                    "capabilities": capabilities
                }
        except Exception as e:
            return {"error": "NETCONF connection failed", "device": device_name, "details": str(e)}

    result = await asyncio.to_thread(_get_capabilities)
    return json.dumps(result, indent=2)


async def get_bgp_neighbors_netconf(device_name: str) -> str:
    """Get BGP neighbors via NETCONF with structured data"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "NETCONF only supported for IOS-XE devices"})

    def _get_bgp_neighbors():
        try:
            with get_netconf_connection(device_name) as m:
                bgp_filter = """
<network-instances xmlns="http://openconfig.net/yang/network-instance">
  <network-instance>
    <name>default</name>
    <protocols>
      <protocol>
        <identifier xmlns:oc-pol-types="http://openconfig.net/yang/policy-types">oc-pol-types:BGP</identifier>
        <name>65000</name>
      </protocol>
    </protocols>
  </network-instance>
</network-instances>"""

                response = m.get(filter=("subtree", bgp_filter))
                root = ET.fromstring(response.xml)  # nosec B314 — trusted NETCONF device response

                ns = {'oc-ni': 'http://openconfig.net/yang/network-instance'}
                neighbors = root.findall('.//oc-ni:neighbor', ns)

                results = []
                for neighbor in neighbors:
                    address = neighbor.find('oc-ni:neighbor-address', ns)
                    state = neighbor.find('.//oc-ni:session-state', ns)
                    peer_type = neighbor.find('.//oc-ni:peer-type', ns)

                    results.append({
                        "neighbor": address.text if address is not None else "unknown",
                        "state": state.text if state is not None else "unknown",
                        "peer_type": peer_type.text if peer_type is not None else "unknown"
                    })

                return {"device": device_name, "bgp_neighbors": results}

        except Exception as e:
            return {"error": "NETCONF connection failed", "device": device_name, "details": str(e)}

    result = await asyncio.to_thread(_get_bgp_neighbors)
    return json.dumps(result, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": get_interfaces_netconf, "name": "get_interfaces_netconf", "category": "netconf"},
    {"fn": get_netconf_capabilities, "name": "get_netconf_capabilities", "category": "netconf"},
    {"fn": get_bgp_neighbors_netconf, "name": "get_bgp_neighbors_netconf", "category": "netconf"},
]
