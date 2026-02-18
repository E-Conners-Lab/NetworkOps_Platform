"""
Bulk operations: multi-device commands, cache status.
"""
import asyncio
import json
import time

from config.devices import DEVICES, is_containerlab_device
from core import log_event
from core.containerlab import run_command as run_containerlab_command
from core.scrapli_manager import get_ios_xe_connection
from mcp_tools._shared import throttled


async def _send_command_raw(device_name: str, command: str) -> tuple:
    """
    Internal helper to send a command and return raw output.
    Returns tuple: (device_name, command, output_or_error)
    """
    if device_name not in DEVICES:
        return (device_name, command, "Error: Device not found")

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    # Handle containerlab devices
    if is_containerlab_device(device_name):
        output = run_containerlab_command(device_name, command)
        return (device_name, command, output)

    # Handle IOS-XE devices
    if device_type == "cisco_xe":
        try:
            async with get_ios_xe_connection(device_name) as conn:
                response = await conn.send_command(command)
            return (device_name, command, response.result)
        except Exception as e:
            return (device_name, command, f"Error: {str(e)}")

    return (device_name, command, f"Error: Unsupported device type {device_type}")


async def bulk_command(command: str, devices: str = None, device_type: str = None) -> str:
    """
    Execute the same command on multiple devices in parallel.

    Args:
        command: Command to execute on all devices
        devices: Comma-separated device names (e.g., "R1,R2,R3") - if not provided, uses all devices
        device_type: Filter by device type (cisco_xe, linux)

    Returns:
        JSON with results from all devices
    """
    # Determine target devices
    if devices:
        target_devices = [d.strip() for d in devices.split(",")]
        # Validate devices exist
        invalid = [d for d in target_devices if d not in DEVICES]
        if invalid:
            return json.dumps({"error": f"Devices not found: {invalid}"})
    else:
        target_devices = list(DEVICES.keys())

    # Filter by device type if specified
    if device_type:
        target_devices = [
            d for d in target_devices
            if DEVICES[d].get("device_type") == device_type
        ]

    if not target_devices:
        return json.dumps({"error": "No devices match the criteria"})

    start = time.time()

    # Execute command on all devices in parallel
    tasks = [throttled(_send_command_raw(device, command)) for device in target_devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    device_results = {}
    success_count = 0
    error_count = 0

    for device, result in zip(target_devices, results):
        if isinstance(result, Exception):
            device_results[device] = {"status": "error", "error": str(result)}
            error_count += 1
        else:
            _, _, output = result
            if "Error:" in output:
                device_results[device] = {"status": "error", "error": output}
                error_count += 1
            else:
                device_results[device] = {"status": "success", "output": output}
                success_count += 1

    elapsed = time.time() - start

    log_event("bulk_command", None, f"'{command}' on {len(target_devices)} devices", "success", "operator")

    return json.dumps({
        "command": command,
        "elapsed_seconds": round(elapsed, 2),
        "summary": {
            "total_devices": len(target_devices),
            "success": success_count,
            "errors": error_count
        },
        "results": device_results
    }, indent=2)


async def cache_status() -> str:
    """
    Get cache status and statistics (debug tool).

    Returns Redis connection status, key counts, and configuration.
    """
    from config.redis_client import redis_available, REDIS_URL
    from core.device_cache import get_device_cache

    cache = get_device_cache()
    stats = cache.get_stats()
    stats['redis_url'] = REDIS_URL
    stats['redis_available_check'] = redis_available()

    return json.dumps(stats, indent=2)


TOOLS = [
    {"fn": bulk_command, "name": "bulk_command", "category": "operations"},
    {"fn": cache_status, "name": "cache_status", "category": "operations"},
]
