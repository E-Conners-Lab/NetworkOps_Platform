"""
Device management MCP tools.

This module provides basic device interaction tools:
- get_devices: List all devices in inventory
- send_command: Execute show commands
- send_config: Apply configuration changes
- health_check: Check single device health
- health_check_all: Check all devices in parallel
"""
import asyncio
import json
import shlex
import subprocess
import time
from typing import TYPE_CHECKING

import defusedxml.ElementTree as ET

from config.devices import (
    DEVICES,
    CONTAINERLAB_VM,
    is_containerlab_device,
    get_scrapli_device,
)
from core import log_event
from core.containerlab import (
    run_command as run_containerlab_command,
    check_health as check_containerlab_health,
    _validate_shell_safe,
)
from security.command_policy import validate_command
from core.scrapli_manager import get_ios_xe_connection, get_linux_connection
from core.netconf_client import get_netconf_connection
from core.device_cache import get_device_cache

from mcp_tools._shared import throttled, get_semaphore

if TYPE_CHECKING:
    from memory import MemoryStore


# =============================================================================
# Internal Helper Functions
# =============================================================================

def _netconf_health_check_sync(name: str, device: dict) -> dict:
    """
    Synchronous NETCONF health check for a single device.
    Uses interfaces-state YANG model for accurate admin/oper status.
    Designed to be run via asyncio.to_thread for parallel execution.
    """
    result = {
        "device": name,
        "netconf": "unknown",
        "interfaces": {"total": 0, "up": 0, "down": 0},
        "status": "unknown"
    }

    try:
        with get_netconf_connection(name) as m:
            result["netconf"] = "connected"

            # Use interfaces-state for operational data (admin-status, oper-status)
            intf_filter = """<interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>"""
            response = m.get(filter=("subtree", intf_filter))

            root = ET.fromstring(response.xml)
            ns = {'ietf-if': 'urn:ietf:params:xml:ns:yang:ietf-interfaces'}

            interfaces = root.findall('.//ietf-if:interface', ns)

            up_count = 0
            down_count = 0

            for intf in interfaces:
                admin_status = intf.find('ietf-if:admin-status', ns)
                oper_status = intf.find('ietf-if:oper-status', ns)

                # Skip admin-down interfaces (intentionally disabled)
                if admin_status is not None and admin_status.text == "down":
                    continue

                # Count admin-up interfaces by operational status
                if oper_status is not None and oper_status.text == "up":
                    up_count += 1
                else:
                    down_count += 1

            result["interfaces"]["total"] = len(interfaces)
            result["interfaces"]["up"] = up_count
            result["interfaces"]["down"] = down_count

            # Determine health status
            if down_count == 0:
                result["status"] = "healthy"
            elif down_count <= 2:
                result["status"] = "degraded"
            else:
                result["status"] = "critical"

    except Exception as e:
        result["netconf"] = "failed"
        result["status"] = "critical"
        result["error"] = str(e)

    return result


async def _check_single_device_netconf(name: str, device: dict) -> dict:
    """Async wrapper for NETCONF health check - runs sync code in thread pool."""
    device_type = device.get("device_type", "")

    # Cisco and Juniper devices support NETCONF
    if device_type in ("cisco_xe", "juniper_junos"):
        return await asyncio.to_thread(_netconf_health_check_sync, name, device)

    # Fall back to CLI for other devices
    return await _check_single_device(name, device)


async def _check_single_device(name: str, device: dict) -> dict:
    """Internal function to check one device's health (CLI-based, faster)."""
    device_type = device.get("device_type", "")

    # Handle containerlab devices
    if device_type.startswith("containerlab_"):
        return check_containerlab_health(name)

    # Handle Linux devices
    if device_type == "linux":
        try:
            async with get_linux_connection(name) as conn:
                response = await conn.send_command("uptime")
            return {
                "device": name,
                "status": "healthy",
                "output": response.result.strip()
            }
        except Exception as e:
            return {"device": name, "status": "critical", "error": str(e)}

    # Handle Juniper Junos devices
    if device_type == "juniper_junos":
        return await _check_juniper_device(name)

    # Handle HPE devices (Aruba CX, ProCurve, Comware)
    if device_type in ("aruba_aoscx", "hp_procurve", "hp_comware"):
        return await _check_hpe_device(name, device_type)

    # Handle IOS-XE devices (default)
    try:
        async with get_ios_xe_connection(name) as conn:
            uptime_response = await conn.send_command("show version | include uptime")
            intf_response = await conn.send_command("show ip interface brief")

            lines = intf_response.result.splitlines()
            up_count = 0
            down_count = 0
            for line in lines:
                line_lower = line.lower()
                if "administratively" in line_lower:
                    continue  # Skip admin-down interfaces entirely
                if "up" in line_lower:
                    up_count += 1
                elif "down" in line_lower:
                    down_count += 1

        if down_count == 0:
            status = "healthy"
        elif up_count > down_count:
            status = "degraded"
        else:
            status = "critical"

        return {
            "device": name,
            "status": status,
            "uptime": uptime_response.result.strip(),
            "interfaces_up": up_count,
            "interfaces_down": down_count,
        }
    except Exception as e:
        return {"device": name, "status": "critical", "error": str(e)}


async def _check_juniper_device(name: str) -> dict:
    """Health check for Juniper Junos devices using Scrapli."""
    try:
        from core.scrapli_manager import get_junos_connection

        async with get_junos_connection(name) as conn:
            uptime_response = await conn.send_command("show system uptime")
            intf_response = await conn.send_command("show interfaces terse")

        # Parse interface status from 'show interfaces terse'
        lines = intf_response.result.splitlines()
        up_count = 0
        down_count = 0
        for line in lines:
            if not line.strip() or line.startswith("Interface"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                admin_status = parts[1].lower()
                link_status = parts[2].lower()
                if admin_status == "up" and link_status == "up":
                    up_count += 1
                elif admin_status == "up" and link_status == "down":
                    down_count += 1

        if down_count == 0:
            status = "healthy"
        elif up_count > down_count:
            status = "degraded"
        else:
            status = "critical"

        return {
            "device": name,
            "status": status,
            "platform": "Juniper Junos",
            "uptime": uptime_response.result.strip()[:200],
            "interfaces_up": up_count,
            "interfaces_down": down_count,
        }
    except Exception as e:
        return {"device": name, "status": "critical", "error": str(e)}


async def _check_hpe_device(name: str, device_type: str) -> dict:
    """Health check for HPE devices using Netmiko."""
    try:
        from core.netmiko_manager import check_hpe_health
        return await check_hpe_health(name, device_type)
    except Exception as e:
        return {"device": name, "status": "critical", "error": str(e)}


# =============================================================================
# MCP Tool Functions
# =============================================================================

def get_devices() -> list[str]:
    """Return a list of all devices in the inventory."""
    return list(DEVICES.keys())


async def send_command(device_name: str, command: str) -> str:
    """Send a command to a device and return the output."""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    # Validate command against allow-list
    is_valid, error_msg = validate_command(command, ["run_show_commands"])
    if not is_valid:
        log_event("command_blocked", device_name, f"MCP blocked: {command[:200]} ({error_msg})", "forbidden", "mcp")
        return json.dumps({"error": error_msg, "status": "forbidden"})

    # Handle containerlab devices
    if is_containerlab_device(device_name):
        output = run_containerlab_command(device_name, command)
        log_event("command", device_name, f"Executed: {command}", "success", "operator")
        return output

    # Handle Linux devices
    if device_type == "linux":
        try:
            async with get_linux_connection(device_name) as conn:
                response = await conn.send_command(command)
            log_event("command", device_name, f"Executed: {command}", "success", "operator")
            return response.result
        except Exception as e:
            return json.dumps({"device": device_name, "error": str(e)})

    # Handle IOS-XE devices
    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(command)

        log_event("command", device_name, f"Executed: {command}", "success", "operator")
        return json.dumps({
            "device": device_name,
            "command": command,
            "output": response.result
        }, indent=2)
    except Exception as e:
        return json.dumps({"device": device_name, "error": str(e)}, indent=2)


async def send_config(device_name: str, commands: str) -> str:
    """Send configuration commands to a device."""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    # Validate each config command against allow-list
    # Config mode lines can start with operator prefixes (e.g. 'ip address'),
    # so we grant both permissions for the validation check.
    for line in commands.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        is_valid, error_msg = validate_command(line, ["run_config_commands", "run_show_commands"])
        if not is_valid:
            log_event("config_blocked", device_name, f"MCP blocked config: {line[:200]} ({error_msg})", "forbidden", "mcp")
            return json.dumps({"error": f"Command '{line}': {error_msg}", "status": "forbidden"})

    # Handle containerlab devices
    if is_containerlab_device(device_name):
        container = device.get("container")

        # Validate commands for shell injection before interpolation
        safe, reason = _validate_shell_safe(commands)
        if not safe:
            return json.dumps({"error": f"Command blocked - {reason}"})

        if device_type == "containerlab_frr":
            config_commands = commands.strip().replace('\n', '\\n')
            docker_cmd = f'sudo docker exec {shlex.quote(container)} vtysh -c "conf t" -c "{config_commands}" -c "end" -c "write"'
        elif device_type == "containerlab_srlinux":
            config_commands = commands.strip()
            docker_cmd = f'sudo docker exec {shlex.quote(container)} bash -c \'echo "enter candidate\\n{config_commands}\\ncommit now" | sr_cli\''
        else:
            return json.dumps({"error": f"Config mode not supported for {device_type}"})

        try:
            result = subprocess.run(
                ["multipass", "exec", CONTAINERLAB_VM, "--", "bash", "-c", docker_cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            log_event("config", device_name, f"Applied config: {commands[:50]}...", "success", "admin")
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return json.dumps({"error": str(e)})

    # Handle IOS-XE devices
    if device_type == "cisco_xe":
        try:
            async with get_ios_xe_connection(device_name) as conn:
                commands_list = commands.strip().split('\n')
                response = await conn.send_configs(commands_list)

            log_event("config", device_name, f"Applied config: {commands[:50]}...", "success", "admin")
            return json.dumps({
                "device": device_name,
                "status": "success",
                "output": response.result
            }, indent=2)
        except Exception as e:
            return json.dumps({"device": device_name, "error": str(e)}, indent=2)

    return json.dumps({"error": f"Config not supported for device type: {device_type}"})


async def health_check(device_name: str) -> str:
    """Check health of a single device."""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    # Check cache first
    cache = get_device_cache()
    cached_result = await cache.get_health(device_name)
    if cached_result:
        cached_result['_from_cache'] = True
        log_event("health_check", device_name, f"Status: {cached_result.get('status')} (cached)", "success", "system")
        return json.dumps(cached_result, indent=2)

    # Cache miss - fetch from device
    device = get_scrapli_device(device_name)
    result = await _check_single_device(device_name, device)

    # Cache the result
    await cache.set_health(device_name, result)

    log_event("health_check", device_name, f"Status: {result.get('status')}", "success", "system")
    return json.dumps(result, indent=2)


async def health_check_all(use_netconf: bool = False) -> str:
    """
    Check health of all devices in parallel.

    Args:
        use_netconf: If True, use NETCONF for Cisco devices (more accurate, matches sync server).
                     If False (default), use CLI (faster).
    """
    start = time.time()

    cache = get_device_cache()
    device_names = list(DEVICES.keys())

    # Check cache for all devices first (batch operation)
    cached_results = await cache.get_health_batch(device_names)
    cache_hits = sum(1 for v in cached_results.values() if v is not None)

    # Identify which devices need fresh checks
    devices_to_check = [name for name, cached in cached_results.items() if cached is None]

    # Choose health check function based on mode
    if use_netconf:
        check_func = _check_single_device_netconf
    else:
        check_func = _check_single_device

    # Only fetch uncached devices
    fresh_results = {}
    if devices_to_check:
        tasks = [throttled(check_func(name, get_scrapli_device(name))) for name in devices_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, result in zip(devices_to_check, results):
            if isinstance(result, Exception):
                fresh_results[name] = {"device": name, "status": "critical", "error": str(result)}
            else:
                fresh_results[name] = result
                # Cache the fresh result
                await cache.set_health(name, result)

    elapsed = time.time() - start

    # Combine cached and fresh results
    devices = []
    for name in device_names:
        if cached_results[name]:
            result = cached_results[name]
            result['_from_cache'] = True
            devices.append(result)
        elif name in fresh_results:
            devices.append(fresh_results[name])
        else:
            devices.append({"device": name, "status": "critical", "error": "No result"})

    summary = {
        "healthy": sum(1 for d in devices if d.get("status") == "healthy"),
        "degraded": sum(1 for d in devices if d.get("status") == "degraded"),
        "critical": sum(1 for d in devices if d.get("status") == "critical"),
    }

    log_event("health_check_all", None, f"Checked {len(DEVICES)} devices ({cache_hits} cached)", "success", "system")

    return json.dumps({
        "mode": "netconf" if use_netconf else "cli",
        "elapsed_seconds": round(elapsed, 2),
        "cache_hits": cache_hits,
        "cache_misses": len(devices_to_check),
        "summary": summary,
        "devices": devices
    }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": get_devices, "name": "get_devices", "category": "device"},
    {"fn": send_command, "name": "send_command", "category": "device"},
    {"fn": send_config, "name": "send_config", "category": "device"},
    {"fn": health_check, "name": "health_check", "category": "device"},
    {"fn": health_check_all, "name": "health_check_all", "category": "device"},
]
