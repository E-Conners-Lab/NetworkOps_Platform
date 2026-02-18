"""
Juniper NETCONF operations using native Junos YANG models.

Juniper uses different YANG models than Cisco:
- Junos native: configuration, interface-information, route-information
- OpenConfig: openconfig-interfaces, openconfig-bgp (also supported)

This module provides Juniper-specific NETCONF filters and parsers.

Usage:
    from core.juniper_netconf import (
        get_junos_interfaces,
        get_junos_bgp_neighbors,
        JUNOS_INTERFACE_FILTER,
    )

    interfaces = get_junos_interfaces("vMX-1")
"""

import defusedxml.ElementTree as ET
from typing import Optional

from core.netconf_client import get_netconf_connection


# =============================================================================
# Junos NETCONF Filters
# =============================================================================

# Junos native interface operational data
JUNOS_INTERFACE_FILTER = """
<interface-information xmlns="http://xml.juniper.net/junos/*/junos-interface">
</interface-information>
"""

# Junos native BGP summary
JUNOS_BGP_SUMMARY_FILTER = """
<bgp-information xmlns="http://xml.juniper.net/junos/*/junos-routing">
</bgp-information>
"""

# Junos native routing table
JUNOS_ROUTE_FILTER = """
<route-information xmlns="http://xml.juniper.net/junos/*/junos-routing">
</route-information>
"""

# Junos system information (uptime, version, etc.)
JUNOS_SYSTEM_FILTER = """
<system-information xmlns="http://xml.juniper.net/junos/*/junos-system">
</system-information>
"""


# =============================================================================
# Junos Namespace Prefixes
# =============================================================================

JUNOS_NAMESPACES = {
    "junos-intf": "http://xml.juniper.net/junos/*/junos-interface",
    "junos-rt": "http://xml.juniper.net/junos/*/junos-routing",
    "junos-sys": "http://xml.juniper.net/junos/*/junos-system",
}


# =============================================================================
# Interface Operations
# =============================================================================

def get_junos_interfaces(device_name: str) -> list[dict]:
    """Get interface information from Juniper device via NETCONF.

    Args:
        device_name: Device name from inventory

    Returns:
        List of interface dicts with name, admin_status, oper_status, etc.
    """
    with get_netconf_connection(device_name) as m:
        response = m.get(filter=("subtree", JUNOS_INTERFACE_FILTER))
        return _parse_junos_interfaces(response.xml)


def _parse_junos_interfaces(xml_str: str) -> list[dict]:
    """Parse Junos interface XML into structured dict.

    Junos interface XML structure:
    <interface-information>
        <physical-interface>
            <name>ge-0/0/0</name>
            <admin-status>up</admin-status>
            <oper-status>up</oper-status>
            <description>Uplink to R1</description>
            <mtu>1514</mtu>
            <logical-interface>
                <name>ge-0/0/0.0</name>
                <address-family>
                    <address-family-name>inet</address-family-name>
                    <interface-address>
                        <ifa-local>10.0.0.1/30</ifa-local>
                    </interface-address>
                </address-family>
            </logical-interface>
        </physical-interface>
    </interface-information>

    Args:
        xml_str: Raw XML response

    Returns:
        List of interface dicts
    """
    interfaces = []

    try:
        root = ET.fromstring(xml_str)

        # Find all physical-interface elements (use local-name for namespace flexibility)
        for intf in root.iter():
            if intf.tag.endswith("physical-interface"):
                intf_dict = {
                    "name": "",
                    "admin_status": "",
                    "oper_status": "",
                    "description": "",
                    "mtu": "",
                    "addresses": [],
                }

                for child in intf:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if tag == "name":
                        intf_dict["name"] = child.text or ""
                    elif tag == "admin-status":
                        intf_dict["admin_status"] = child.text or ""
                    elif tag == "oper-status":
                        intf_dict["oper_status"] = child.text or ""
                    elif tag == "description":
                        intf_dict["description"] = child.text or ""
                    elif tag == "mtu":
                        intf_dict["mtu"] = child.text or ""
                    elif tag == "logical-interface":
                        # Parse logical interface for IP addresses
                        for addr_elem in child.iter():
                            addr_tag = addr_elem.tag.split("}")[-1] if "}" in addr_elem.tag else addr_elem.tag
                            if addr_tag == "ifa-local" and addr_elem.text:
                                intf_dict["addresses"].append(addr_elem.text)

                if intf_dict["name"]:
                    interfaces.append(intf_dict)

    except ET.ParseError:
        pass

    return interfaces


# =============================================================================
# BGP Operations
# =============================================================================

def get_junos_bgp_neighbors(device_name: str) -> list[dict]:
    """Get BGP neighbor information from Juniper device via NETCONF.

    Args:
        device_name: Device name from inventory

    Returns:
        List of BGP neighbor dicts
    """
    with get_netconf_connection(device_name) as m:
        response = m.get(filter=("subtree", JUNOS_BGP_SUMMARY_FILTER))
        return _parse_junos_bgp(response.xml)


def _parse_junos_bgp(xml_str: str) -> list[dict]:
    """Parse Junos BGP XML into structured dict.

    Args:
        xml_str: Raw XML response

    Returns:
        List of BGP neighbor dicts
    """
    neighbors = []

    try:
        root = ET.fromstring(xml_str)

        for peer in root.iter():
            if peer.tag.endswith("bgp-peer"):
                peer_dict = {
                    "neighbor_address": "",
                    "peer_as": "",
                    "state": "",
                    "description": "",
                }

                for child in peer:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if tag == "peer-address":
                        peer_dict["neighbor_address"] = child.text or ""
                    elif tag == "peer-as":
                        peer_dict["peer_as"] = child.text or ""
                    elif tag == "peer-state":
                        peer_dict["state"] = child.text or ""
                    elif tag == "description":
                        peer_dict["description"] = child.text or ""

                if peer_dict["neighbor_address"]:
                    neighbors.append(peer_dict)

    except ET.ParseError:
        pass

    return neighbors


# =============================================================================
# Health Check Helper
# =============================================================================

def parse_junos_health_check(xml_str: str) -> tuple[int, int]:
    """Parse Junos interface XML for health check.

    Args:
        xml_str: Raw XML response from interface query

    Returns:
        Tuple of (up_count, down_count)
    """
    up_count = 0
    down_count = 0

    try:
        root = ET.fromstring(xml_str)

        for intf in root.iter():
            if intf.tag.endswith("physical-interface"):
                admin_status = ""
                oper_status = ""

                for child in intf:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if tag == "admin-status":
                        admin_status = (child.text or "").lower()
                    elif tag == "oper-status":
                        oper_status = (child.text or "").lower()

                # Only count admin-up interfaces
                if admin_status == "up":
                    if oper_status == "up":
                        up_count += 1
                    else:
                        down_count += 1

    except ET.ParseError:
        pass

    return up_count, down_count
