"""
NETCONF client connection management.

Consolidates ncclient connection patterns previously duplicated across:
- network_mcp_async.py (4 instances)
- dashboard/api_server.py (1 instance)

Usage:
    from core.netconf_client import (
        get_netconf_connection,
        netconf_get,
    )

    # Context manager for automatic cleanup
    with get_netconf_connection("R1") as m:
        response = m.get(filter=("subtree", filter_xml))

    # Simple query helper
    result = netconf_get("R1", filter_xml)
"""

from contextlib import contextmanager
from typing import Iterator, Optional

from ncclient import manager
from ncclient.manager import Manager

from config.devices import DEVICES, USERNAME, PASSWORD


# Default NETCONF settings
NETCONF_PORT = 830
NETCONF_TIMEOUT = 10

# Vendor-specific NETCONF settings
# ncclient uses device_params to select the appropriate NETCONF handler
NETCONF_DEVICE_PARAMS = {
    "cisco_xe": {"name": "iosxe"},
    "juniper_junos": {"name": "junos"},
}

# Device types that support NETCONF
NETCONF_CAPABLE_TYPES = ["cisco_xe", "juniper_junos"]


def is_netconf_capable(device_name: str) -> bool:
    """Check if device supports NETCONF.

    Args:
        device_name: Device name

    Returns:
        True if device type supports NETCONF
    """
    device = DEVICES.get(device_name)
    if device is None:
        return False
    return device.get("device_type", "") in NETCONF_CAPABLE_TYPES


def _get_netconf_params(device_name: str) -> dict:
    """Get connection parameters for NETCONF device."""
    if device_name not in DEVICES:
        raise ValueError(f"Device '{device_name}' not found in inventory")

    device = DEVICES[device_name]
    device_type = device.get("device_type", "cisco_xe")

    # Get vendor-specific device_params for ncclient
    device_params = NETCONF_DEVICE_PARAMS.get(device_type, {"name": "default"})

    return {
        "host": device["host"],
        "port": NETCONF_PORT,
        "username": USERNAME,
        "password": PASSWORD,
        "hostkey_verify": False,
        "timeout": NETCONF_TIMEOUT,
        "device_params": device_params,
    }


@contextmanager
def get_netconf_connection(
    device_name: str,
    timeout: Optional[int] = None
) -> Iterator[Manager]:
    """
    Context manager for NETCONF device connections.

    Uses a connection pool to reuse SSH/NETCONF sessions across operations.

    Args:
        device_name: Name of the device (e.g., "R1", "Switch-R1")
        timeout: Optional timeout override (default: 10 seconds)

    Yields:
        ncclient Manager connection

    Example:
        with get_netconf_connection("R1") as m:
            response = m.get(filter=("subtree", interface_filter))
            capabilities = list(m.server_capabilities)
    """
    from core.netconf_pool import pooled_netconf_connection

    with pooled_netconf_connection(device_name, timeout) as m:
        yield m


def netconf_connect(
    device_name: str,
    timeout: Optional[int] = None
) -> Manager:
    """
    Create a NETCONF connection (caller must close).

    Args:
        device_name: Name of the device
        timeout: Optional timeout override

    Returns:
        ncclient Manager connection

    Note:
        Caller is responsible for calling m.close_session()
        Prefer get_netconf_connection() context manager when possible.
    """
    params = _get_netconf_params(device_name)
    if timeout is not None:
        params["timeout"] = timeout

    return manager.connect(**params)


def netconf_get(device_name: str, filter_xml: str) -> str:
    """
    Execute a NETCONF get operation with subtree filter.

    Args:
        device_name: Name of the device
        filter_xml: XML filter string

    Returns:
        Response XML as string

    Example:
        xml = netconf_get("R1", '<interfaces xmlns="..."/>')
    """
    with get_netconf_connection(device_name) as m:
        response = m.get(filter=("subtree", filter_xml))
        return response.xml


def netconf_get_capabilities(device_name: str) -> list[str]:
    """
    Get list of NETCONF capabilities from device.

    Args:
        device_name: Name of the device

    Returns:
        List of capability URIs
    """
    with get_netconf_connection(device_name) as m:
        return list(m.server_capabilities)
