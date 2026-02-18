"""
Scrapli SSH connection management.

Consolidates Scrapli connection patterns previously duplicated across:
- network_mcp_async.py (11 instances)
- rag/network_tools.py (2 instances)

Usage:
    from core.scrapli_manager import (
        get_ios_xe_connection,
        get_linux_connection,
        send_command,
        send_commands,
    )

    # Context manager for IOS-XE (creates new connection each time)
    async with get_ios_xe_connection("R1") as conn:
        response = await conn.send_command("show version")

    # Simple command execution (uses connection pool for efficiency)
    output = await send_command("R1", "show ip route")

    # Multiple commands
    outputs = await send_commands("R1", ["show ip route", "show ip int brief"])

    # Pooled connection (recommended for high-concurrency)
    from core.scrapli_manager import pooled_connection
    async with pooled_connection("R1") as conn:
        response = await conn.send_command("show version")
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from scrapli.driver.core import AsyncIOSXEDriver, AsyncJunosDriver
from scrapli.driver.generic import AsyncGenericDriver
from scrapli.response import Response

from config.devices import DEVICES, get_scrapli_device, HPE_TYPES, SSH_STRICT_KEY

# Re-export pooled connection for convenience
from core.connection_pool import (
    pooled_connection,
    get_connection_pool,
    pool_stats,
    pool_cleanup,
    pool_close_all,
)

# Feature flag for using connection pool
USE_CONNECTION_POOL = os.getenv("USE_CONNECTION_POOL", "true").lower() == "true"


def _get_ios_xe_params(device_name: str) -> dict:
    """Get connection parameters for IOS-XE device, filtering out device_type."""
    scrapli_device = get_scrapli_device(device_name)
    return {k: v for k, v in scrapli_device.items() if k != "device_type"}


def _get_linux_params(device_name: str) -> dict:
    """Get connection parameters for Linux device."""
    scrapli_device = get_scrapli_device(device_name)
    return {
        "host": scrapli_device["host"],
        "auth_username": scrapli_device["auth_username"],
        "auth_password": scrapli_device["auth_password"],
        "auth_strict_key": SSH_STRICT_KEY,
        "transport": "asyncssh",
        "timeout_socket": 10,
        "timeout_transport": 10,
    }


def _get_junos_params(device_name: str) -> dict:
    """Get connection parameters for Juniper Junos device."""
    scrapli_device = get_scrapli_device(device_name)
    return {
        "host": scrapli_device["host"],
        "auth_username": scrapli_device["auth_username"],
        "auth_password": scrapli_device["auth_password"],
        "auth_strict_key": SSH_STRICT_KEY,
        "transport": "asyncssh",
        "timeout_socket": 10,
        "timeout_transport": 10,
    }


@asynccontextmanager
async def get_ios_xe_connection(device_name: str) -> AsyncIterator[AsyncIOSXEDriver]:
    """
    Async context manager for IOS-XE device connections.

    Args:
        device_name: Name of the device (e.g., "R1", "Switch-R1")

    Yields:
        AsyncIOSXEDriver connection (or DemoConnection in demo mode)

    Example:
        async with get_ios_xe_connection("R1") as conn:
            response = await conn.send_command("show version")
            print(response.result)
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        yield DemoConnection(device_name)
        return

    params = _get_ios_xe_params(device_name)
    async with AsyncIOSXEDriver(**params) as conn:
        yield conn


@asynccontextmanager
async def get_linux_connection(device_name: str) -> AsyncIterator[AsyncGenericDriver]:
    """
    Async context manager for Linux device connections.

    Args:
        device_name: Name of the device (e.g., "Alpine-1", "Docker-1")

    Yields:
        AsyncGenericDriver connection (or DemoConnection in demo mode)

    Example:
        async with get_linux_connection("Alpine-1") as conn:
            response = await conn.send_command("uptime")
            print(response.result)
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        yield DemoConnection(device_name)
        return

    params = _get_linux_params(device_name)
    async with AsyncGenericDriver(**params) as conn:
        yield conn


@asynccontextmanager
async def get_junos_connection(device_name: str) -> AsyncIterator[AsyncJunosDriver]:
    """
    Async context manager for Juniper Junos device connections.

    Uses native Scrapli AsyncJunosDriver for proper Junos CLI handling.

    Args:
        device_name: Name of the device (e.g., "vMX-1", "SRX-1")

    Yields:
        AsyncJunosDriver connection (or DemoConnection in demo mode)

    Example:
        async with get_junos_connection("vMX-1") as conn:
            response = await conn.send_command("show version")
            print(response.result)
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        yield DemoConnection(device_name)
        return

    params = _get_junos_params(device_name)
    async with AsyncJunosDriver(**params) as conn:
        yield conn


async def send_command(
    device_name: str,
    command: str,
    device_type: Optional[str] = None,
    use_pool: Optional[bool] = None,
) -> Response:
    """
    Send a single command to a device and return the response.

    Uses connection pooling by default for better performance under load.

    Args:
        device_name: Name of the device
        command: Command to execute
        device_type: Optional device type override (auto-detected if not provided)
        use_pool: Override connection pool usage (default: USE_CONNECTION_POOL env var)

    Returns:
        Scrapli Response object

    Example:
        response = await send_command("R1", "show ip route")
        print(response.result)
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        conn = DemoConnection(device_name)
        return await conn.send_command(command)

    if device_type is None:
        device = DEVICES.get(device_name, {})
        device_type = device.get("device_type", "cisco_xe")

    # Determine whether to use pool
    should_use_pool = use_pool if use_pool is not None else USE_CONNECTION_POOL

    # HPE devices use Netmiko - delegate to netmiko_manager
    if device_type in HPE_TYPES:
        from core.netmiko_manager import send_command_netmiko
        return await send_command_netmiko(device_name, command)

    # Juniper uses native Scrapli driver (no pool support yet)
    if device_type == "juniper_junos":
        async with get_junos_connection(device_name) as conn:
            return await conn.send_command(command)

    # Linux uses generic driver
    if device_type == "linux":
        async with get_linux_connection(device_name) as conn:
            return await conn.send_command(command)

    # Cisco IOS-XE - use pool if enabled
    if should_use_pool:
        async with pooled_connection(device_name) as conn:
            return await conn.send_command(command)
    else:
        async with get_ios_xe_connection(device_name) as conn:
            return await conn.send_command(command)


async def send_commands(
    device_name: str,
    commands: list[str],
    device_type: Optional[str] = None,
    use_pool: Optional[bool] = None,
) -> list[Response]:
    """
    Send multiple commands to a device and return the responses.

    Uses connection pooling by default for better performance under load.

    Args:
        device_name: Name of the device
        commands: List of commands to execute
        device_type: Optional device type override
        use_pool: Override connection pool usage (default: USE_CONNECTION_POOL env var)

    Returns:
        List of Scrapli Response objects
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        conn = DemoConnection(device_name)
        return await conn.send_commands(commands)

    if device_type is None:
        device = DEVICES.get(device_name, {})
        device_type = device.get("device_type", "cisco_xe")

    # Determine whether to use pool
    should_use_pool = use_pool if use_pool is not None else USE_CONNECTION_POOL

    # HPE devices use Netmiko - delegate to netmiko_manager
    if device_type in HPE_TYPES:
        from core.netmiko_manager import send_commands_netmiko
        return await send_commands_netmiko(device_name, commands)

    # Juniper uses native Scrapli driver (no pool support yet)
    if device_type == "juniper_junos":
        async with get_junos_connection(device_name) as conn:
            return [await conn.send_command(cmd) for cmd in commands]

    # Linux uses generic driver
    if device_type == "linux":
        async with get_linux_connection(device_name) as conn:
            return [await conn.send_command(cmd) for cmd in commands]

    # Cisco IOS-XE - use pool if enabled
    if should_use_pool:
        async with pooled_connection(device_name) as conn:
            return [await conn.send_command(cmd) for cmd in commands]
    else:
        async with get_ios_xe_connection(device_name) as conn:
            return [await conn.send_command(cmd) for cmd in commands]


async def send_config(
    device_name: str,
    configs: list[str],
) -> Response:
    """
    Send configuration commands to an IOS-XE device.

    Args:
        device_name: Name of the device
        configs: List of configuration commands

    Returns:
        Scrapli Response object
    """
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.connection import DemoConnection
        conn = DemoConnection(device_name)
        return await conn.send_configs(configs)

    async with get_ios_xe_connection(device_name) as conn:
        return await conn.send_configs(configs)
