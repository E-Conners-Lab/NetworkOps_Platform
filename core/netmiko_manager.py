"""
Netmiko SSH connection management for HPE devices.

Provides async wrappers around Netmiko for devices without native Scrapli support:
- HPE Aruba CX (aruba_aoscx -> aruba_osswitch driver)
- HPE ProCurve (hp_procurve)
- HPE Comware (hp_comware)

Uses asyncio.to_thread() to wrap synchronous Netmiko calls for async compatibility.
Includes retry with exponential backoff for transient failures.

Usage:
    from core.netmiko_manager import send_command_netmiko, send_config_netmiko

    # Send show command
    output = await send_command_netmiko("Aruba-CX-1", "show version")

    # Send config commands
    output = await send_config_netmiko("Aruba-CX-1", ["interface 1/1/1", "no shutdown"])
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from config.devices import DEVICES, USERNAME, PASSWORD, _get_netmiko_device_type


# =============================================================================
# Response Wrapper
# =============================================================================

@dataclass
class NetmikoResponse:
    """Wrapper to match Scrapli Response interface for compatibility."""
    result: str
    failed: bool = False
    channel_input: str = ""

    def __str__(self) -> str:
        return self.result


# =============================================================================
# Connection Parameters
# =============================================================================

def _get_netmiko_params(device_name: str) -> dict:
    """Get Netmiko connection parameters for device.

    Args:
        device_name: Device name from inventory

    Returns:
        Dict of Netmiko connection parameters

    Raises:
        ValueError: If device not found in inventory
    """
    device = DEVICES.get(device_name)
    if device is None:
        raise ValueError(f"Device '{device_name}' not found in inventory")

    device_type = device.get("device_type", "")
    netmiko_type = _get_netmiko_device_type(device_type)

    return {
        "device_type": netmiko_type,
        "host": device["host"],
        "username": USERNAME,
        "password": PASSWORD,
        "timeout": 30,
        "session_timeout": 60,
        "auth_timeout": 30,
    }


# =============================================================================
# Retry Configuration
# =============================================================================

# Retry on transient network errors, not on auth failures
RETRYABLE_EXCEPTIONS = (
    NetmikoTimeoutException,
    ConnectionRefusedError,
    ConnectionResetError,
    TimeoutError,
    OSError,
)


def _is_auth_error(exception: Exception) -> bool:
    """Check if exception is an authentication error (should not retry)."""
    return isinstance(exception, NetmikoAuthenticationException)


# =============================================================================
# Async Command Functions
# =============================================================================

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
    reraise=True,
)
def _sync_send_command(device_name: str, command: str) -> str:
    """Synchronous command execution with retry.

    Args:
        device_name: Device to connect to
        command: Command to execute

    Returns:
        Command output string
    """
    params = _get_netmiko_params(device_name)
    with ConnectHandler(**params) as conn:
        return conn.send_command(command)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
    reraise=True,
)
def _sync_send_commands(device_name: str, commands: list[str]) -> list[str]:
    """Synchronous multiple command execution with retry.

    Args:
        device_name: Device to connect to
        commands: List of commands to execute

    Returns:
        List of command output strings
    """
    params = _get_netmiko_params(device_name)
    results = []
    with ConnectHandler(**params) as conn:
        for cmd in commands:
            results.append(conn.send_command(cmd))
    return results


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=4),
    retry=retry_if_exception_type(RETRYABLE_EXCEPTIONS),
    reraise=True,
)
def _sync_send_config(device_name: str, commands: list[str]) -> str:
    """Synchronous config command execution with retry.

    Args:
        device_name: Device to connect to
        commands: List of config commands

    Returns:
        Config output string
    """
    params = _get_netmiko_params(device_name)
    with ConnectHandler(**params) as conn:
        return conn.send_config_set(commands)


async def send_command_netmiko(
    device_name: str,
    command: str,
) -> NetmikoResponse:
    """Send a single command to an HPE device using Netmiko.

    Wraps synchronous Netmiko in asyncio.to_thread for async compatibility.
    Includes retry with exponential backoff for transient failures.

    Args:
        device_name: Name of the device
        command: Command to execute

    Returns:
        NetmikoResponse with result attribute

    Raises:
        NetmikoAuthenticationException: On authentication failure (no retry)
        NetmikoTimeoutException: After 3 retry attempts fail
    """
    try:
        result = await asyncio.to_thread(_sync_send_command, device_name, command)
        return NetmikoResponse(result=result, channel_input=command)
    except Exception as e:
        return NetmikoResponse(result=str(e), failed=True, channel_input=command)


async def send_commands_netmiko(
    device_name: str,
    commands: list[str],
) -> list[NetmikoResponse]:
    """Send multiple commands to an HPE device using Netmiko.

    Args:
        device_name: Name of the device
        commands: List of commands to execute

    Returns:
        List of NetmikoResponse objects
    """
    try:
        results = await asyncio.to_thread(_sync_send_commands, device_name, commands)
        return [
            NetmikoResponse(result=result, channel_input=cmd)
            for result, cmd in zip(results, commands)
        ]
    except Exception as e:
        return [
            NetmikoResponse(result=str(e), failed=True, channel_input=cmd)
            for cmd in commands
        ]


async def send_config_netmiko(
    device_name: str,
    commands: list[str],
) -> NetmikoResponse:
    """Send configuration commands to an HPE device.

    Args:
        device_name: Name of the device
        commands: List of configuration commands

    Returns:
        NetmikoResponse with config output
    """
    try:
        result = await asyncio.to_thread(_sync_send_config, device_name, commands)
        return NetmikoResponse(result=result, channel_input="\n".join(commands))
    except Exception as e:
        return NetmikoResponse(
            result=str(e), failed=True, channel_input="\n".join(commands)
        )


# =============================================================================
# Health Check
# =============================================================================

async def check_hpe_health(device_name: str, device_type: str) -> dict:
    """Check health of an HPE device.

    Args:
        device_name: Device name
        device_type: Device type (aruba_aoscx, hp_procurve, hp_comware)

    Returns:
        Health check result dict with status, interfaces, etc.
    """
    try:
        # Comware uses 'display', others use 'show'
        if device_type == "hp_comware":
            version_cmd = "display version"
            intf_cmd = "display interface brief"
        else:
            version_cmd = "show version"
            intf_cmd = "show interface brief"

        version_response = await send_command_netmiko(device_name, version_cmd)
        intf_response = await send_command_netmiko(device_name, intf_cmd)

        if version_response.failed:
            return {
                "device": device_name,
                "status": "critical",
                "error": version_response.result,
            }

        # Parse interface status (basic up/down count)
        lines = intf_response.result.splitlines()
        up_count = sum(1 for line in lines if "up" in line.lower())
        down_count = sum(1 for line in lines if "down" in line.lower())

        status = "healthy" if down_count == 0 else "degraded"

        return {
            "device": device_name,
            "status": status,
            "platform": _get_platform_name(device_type),
            "interfaces": {"up": up_count, "down": down_count},
        }
    except Exception as e:
        return {
            "device": device_name,
            "status": "critical",
            "error": str(e),
        }


def _get_platform_name(device_type: str) -> str:
    """Get human-readable platform name."""
    names = {
        "aruba_aoscx": "HPE Aruba CX",
        "hp_procurve": "HPE ProCurve",
        "hp_comware": "HPE Comware",
    }
    return names.get(device_type, device_type)
