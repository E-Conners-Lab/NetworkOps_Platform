"""
Network tools integration for RAG chatbot.

Provides live network data access through MCP-style tool definitions
that Claude can call during response generation.
"""

import logging
import sys
from pathlib import Path
from typing import Any

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.devices import DEVICES

logger = logging.getLogger(__name__)


# Tool permission requirements for RAG chatbot tools.
# This is intentionally separate from security.tool_permissions (MCP layer)
# because the RAG chatbot's send_command is already hardcoded to show-only
# at the function level (_send_command rejects non-show commands), so it
# doesn't need a permission gate here.
TOOL_PERMISSIONS = {
    'get_devices': None,
    'health_check': None,
    'send_command': None,  # Already restricted to show commands in _send_command()
    'get_interface_status': None,
    'get_hierarchy': None,
    'get_device_location': None,
    'get_netbox_ips': None,
    'send_config': 'run_config_commands',
    'remediate_interface': 'remediate_interfaces',
}


# Read-only tool definitions for Claude
NETWORK_TOOLS = [
    {
        "name": "get_devices",
        "description": "Get a list of all network devices in the lab inventory with their IP addresses and types",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "health_check",
        "description": "Check the health status of a specific network device. Returns connectivity status and basic info.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., 'R1', 'R2', 'Switch-R1', 'Alpine-1')"
                }
            },
            "required": ["device_name"]
        }
    },
    {
        "name": "send_command",
        "description": "Send a show command to a network device and return the output. Use for checking interface status, routing tables, OSPF neighbors, BGP status, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., 'R1', 'R2', 'R3', 'R4')"
                },
                "command": {
                    "type": "string",
                    "description": "The show command to execute (e.g., 'show ip interface brief', 'show ip ospf neighbor', 'show ip route')"
                }
            },
            "required": ["device_name", "command"]
        }
    },
    {
        "name": "get_interface_status",
        "description": "Get detailed status of a specific interface on a device",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device"
                },
                "interface": {
                    "type": "string",
                    "description": "Interface name (e.g., 'GigabitEthernet1', 'Gi2')"
                }
            },
            "required": ["device_name", "interface"]
        }
    },
    {
        "name": "get_hierarchy",
        "description": "Get the network hierarchy from NetBox showing regions, sites, racks/locations, and which devices are in each. Use this to answer questions about network organization, site locations, or rack assignments.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_device_location",
        "description": "Get the physical location of a specific device from NetBox, including its region, site, and rack/location.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., 'R1', 'Switch-R1')"
                }
            },
            "required": ["device_name"]
        }
    },
    {
        "name": "get_netbox_ips",
        "description": "Get IP addresses assigned to a device from NetBox IPAM. This returns the documented/intended IP addresses from the source of truth, not live device state.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., 'R1', 'R3'). Leave empty to get all IPs."
                }
            },
            "required": []
        }
    },
]


# Admin-only write tools (require special permissions)
WRITE_TOOLS = [
    {
        "name": "send_config",
        "description": "Send configuration commands to a network device. REQUIRES ADMIN PERMISSION. Use this to configure interfaces, routing protocols, access lists, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device (e.g., 'R1', 'R2', 'R3', 'R4')"
                },
                "commands": {
                    "type": "string",
                    "description": "Configuration commands to send, one per line (e.g., 'interface GigabitEthernet3\\nip address 10.0.0.1 255.255.255.0')"
                }
            },
            "required": ["device_name", "commands"]
        }
    },
    {
        "name": "remediate_interface",
        "description": "Remediate an interface issue by performing shutdown, no shutdown, or bounce operations. REQUIRES ADMIN PERMISSION.",
        "input_schema": {
            "type": "object",
            "properties": {
                "device_name": {
                    "type": "string",
                    "description": "Name of the device"
                },
                "interface": {
                    "type": "string",
                    "description": "Interface name (e.g., 'GigabitEthernet1', 'Gi2')"
                },
                "action": {
                    "type": "string",
                    "enum": ["no_shutdown", "shutdown", "bounce"],
                    "description": "Action to perform: 'no_shutdown' to bring up, 'shutdown' to bring down, 'bounce' to restart"
                }
            },
            "required": ["device_name", "interface", "action"]
        }
    },
]


def get_tools_for_permissions(permissions: list) -> list:
    """
    Return tools available for the given permissions.

    Args:
        permissions: List of permission strings (e.g., ['run_config_commands', 'remediate_interfaces'])

    Returns:
        List of tool definitions the user can access
    """
    available_tools = []
    all_tools = NETWORK_TOOLS + WRITE_TOOLS

    for tool in all_tools:
        required_perm = TOOL_PERMISSIONS.get(tool['name'])
        # Tool is available if no permission required OR user has the required permission
        if required_perm is None or required_perm in permissions:
            available_tools.append(tool)

    logger.debug(f"User permissions {permissions} -> {len(available_tools)} tools available")
    return available_tools


async def execute_tool(tool_name: str, tool_input: dict) -> dict:
    """Execute a network tool and return the result."""
    try:
        if tool_name == "get_devices":
            return await _get_devices()
        elif tool_name == "health_check":
            return await _health_check(tool_input.get("device_name"))
        elif tool_name == "send_command":
            return await _send_command(
                tool_input.get("device_name"),
                tool_input.get("command")
            )
        elif tool_name == "get_interface_status":
            return await _get_interface_status(
                tool_input.get("device_name"),
                tool_input.get("interface")
            )
        elif tool_name == "get_hierarchy":
            return await _get_hierarchy()
        elif tool_name == "get_device_location":
            return await _get_device_location(tool_input.get("device_name"))
        elif tool_name == "get_netbox_ips":
            return await _get_netbox_ips(tool_input.get("device_name"))
        elif tool_name == "send_config":
            return await _send_config(
                tool_input.get("device_name"),
                tool_input.get("commands")
            )
        elif tool_name == "remediate_interface":
            return await _remediate_interface(
                tool_input.get("device_name"),
                tool_input.get("interface"),
                tool_input.get("action", "no_shutdown")
            )
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return {"error": str(e)}


async def _get_devices() -> dict:
    """Get list of all devices."""
    devices = []
    for name, config in DEVICES.items():
        devices.append({
            "name": name,
            "host": config.get("host"),
            "device_type": config.get("device_type"),
            "platform": config.get("platform", "cisco_xe")
        })
    return {"devices": devices, "count": len(devices)}


async def _health_check(device_name: str) -> dict:
    """Check health of a specific device."""
    from core.scrapli_manager import get_ios_xe_connection

    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found in inventory"}

    device_config = DEVICES[device_name]
    device_type = device_config.get("device_type", "cisco_xe")

    # Handle Linux devices differently
    if device_type == "linux":
        return await _linux_health_check(device_name, device_config)

    # Cisco device health check
    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command("show version | include uptime")
            return {
                "device": device_name,
                "status": "healthy",
                "uptime": response.result.strip(),
                "reachable": True
            }
    except Exception as e:
        return {
            "device": device_name,
            "status": "unreachable",
            "error": str(e),
            "reachable": False
        }


async def _linux_health_check(device_name: str, config: dict) -> dict:
    """Health check for Linux devices."""
    import asyncssh

    try:
        async with asyncssh.connect(
            config["host"],
            username=config.get("username", "admin"),
            password=config.get("password", "admin"),
            known_hosts=None
        ) as conn:
            result = await conn.run("uptime", check=True)
            return {
                "device": device_name,
                "status": "healthy",
                "uptime": result.stdout.strip(),
                "reachable": True
            }
    except Exception as e:
        return {
            "device": device_name,
            "status": "unreachable",
            "error": str(e),
            "reachable": False
        }


async def _send_command(device_name: str, command: str) -> dict:
    """Send a command to a device."""
    from core.scrapli_manager import get_ios_xe_connection

    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found in inventory"}

    # Only allow show commands for safety
    if not command.strip().lower().startswith("show"):
        return {"error": "Only 'show' commands are allowed for safety"}

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(command)
            return {
                "device": device_name,
                "command": command,
                "output": response.result,
                "success": True
            }
    except Exception as e:
        return {
            "device": device_name,
            "command": command,
            "error": str(e),
            "success": False
        }


async def _get_interface_status(device_name: str, interface: str) -> dict:
    """Get status of a specific interface."""
    result = await _send_command(device_name, f"show interface {interface}")
    if result.get("success"):
        return {
            "device": device_name,
            "interface": interface,
            "output": result["output"],
            "success": True
        }
    return result


async def _send_config(device_name: str, commands: str) -> dict:
    """Send configuration commands to a device. ADMIN ONLY."""
    from core.scrapli_manager import get_ios_xe_connection

    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found in inventory"}

    device_config = DEVICES[device_name]
    device_type = device_config.get("device_type", "cisco_xe")

    # Only allow config on Cisco devices
    if device_type == "linux":
        return {"error": "Configuration commands not supported on Linux devices"}

    # Parse commands (handle both newline and semicolon separated)
    cmd_list = []
    for line in commands.replace(';', '\n').split('\n'):
        line = line.strip()
        if line:
            cmd_list.append(line)

    if not cmd_list:
        return {"error": "No commands provided"}

    logger.info(f"ADMIN: Sending {len(cmd_list)} config commands to {device_name}")

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_configs(cmd_list)
            return {
                "device": device_name,
                "commands_sent": cmd_list,
                "output": response.result,
                "success": True
            }
    except Exception as e:
        logger.error(f"Config error on {device_name}: {e}")
        return {
            "device": device_name,
            "commands_sent": cmd_list,
            "error": str(e),
            "success": False
        }


async def _remediate_interface(device_name: str, interface: str, action: str) -> dict:
    """Remediate an interface (shutdown/no shutdown/bounce). ADMIN ONLY."""
    from core.scrapli_manager import get_ios_xe_connection

    if device_name not in DEVICES:
        return {"error": f"Device '{device_name}' not found in inventory"}

    device_config = DEVICES[device_name]
    device_type = device_config.get("device_type", "cisco_xe")

    if device_type == "linux":
        return {"error": "Interface remediation not supported on Linux devices"}

    # Build commands based on action
    if action == "no_shutdown":
        commands = [f"interface {interface}", "no shutdown"]
    elif action == "shutdown":
        commands = [f"interface {interface}", "shutdown"]
    elif action == "bounce":
        commands = [f"interface {interface}", "shutdown", "no shutdown"]
    else:
        return {"error": f"Invalid action: {action}. Use 'no_shutdown', 'shutdown', or 'bounce'"}

    logger.info(f"ADMIN: Remediating {interface} on {device_name} with action '{action}'")

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_configs(commands)
            return {
                "device": device_name,
                "interface": interface,
                "action": action,
                "output": response.result,
                "success": True
            }
    except Exception as e:
        logger.error(f"Remediation error on {device_name}/{interface}: {e}")
        return {
            "device": device_name,
            "interface": interface,
            "action": action,
            "error": str(e),
            "success": False
        }


async def _get_hierarchy() -> dict:
    """Get network hierarchy from NetBox (regions/sites/racks/devices)."""
    import os
    import aiohttp

    # Try to get hierarchy from API
    api_url = os.getenv("API_URL", "http://localhost:5001")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{api_url}/api/hierarchy", timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "source": data.get("data_source", "unknown"),
                        "regions": data.get("regions", []),
                        "success": True
                    }
                elif resp.status == 403:
                    return {
                        "error": "Hierarchy feature not enabled",
                        "hint": "Set ENABLE_HIERARCHICAL_VIEW=true",
                        "success": False
                    }
                else:
                    return {"error": f"API returned {resp.status}", "success": False}
    except Exception as e:
        logger.error(f"Hierarchy fetch error: {e}")
        # Fallback: try direct NetBox query
        try:
            from config.netbox_client import get_client, is_netbox_available
            if is_netbox_available():
                client = get_client()
                hierarchy = client.get_hierarchy_data()
                return {
                    "source": "netbox_direct",
                    "regions": hierarchy.get("regions", []),
                    "sites": hierarchy.get("sites", []),
                    "racks": hierarchy.get("racks", []),
                    "device_locations": hierarchy.get("device_locations", {}),
                    "success": True
                }
        except Exception as nb_err:
            logger.error(f"NetBox fallback error: {nb_err}")

        return {"error": str(e), "success": False}


async def _get_device_location(device_name: str) -> dict:
    """Get physical location of a device from NetBox."""
    import os
    import aiohttp

    if not device_name:
        return {"error": "Device name required", "success": False}

    api_url = os.getenv("API_URL", "http://localhost:5001")

    try:
        # First get hierarchy to find device location
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{api_url}/api/hierarchy", timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    # Search through hierarchy for device
                    for region in data.get("regions", []):
                        for site in region.get("sites", []):
                            for rack in site.get("racks", []):
                                rack_id = rack.get("id")
                                # Check topology for devices in this rack
                                topo_resp = await session.get(
                                    f"{api_url}/api/topology/level/rack/{rack_id}",
                                    timeout=10
                                )
                                if topo_resp.status == 200:
                                    topo = await topo_resp.json()
                                    for node in topo.get("nodes", []):
                                        if node.get("id") == device_name:
                                            return {
                                                "device": device_name,
                                                "region": region.get("name"),
                                                "site": site.get("name"),
                                                "rack": rack.get("name"),
                                                "success": True
                                            }

                    return {
                        "device": device_name,
                        "error": "Device not found in hierarchy",
                        "success": False
                    }
    except Exception as e:
        logger.error(f"Device location error: {e}")

        # Fallback: try direct NetBox query
        try:
            from config.netbox_client import get_client, is_netbox_available
            if is_netbox_available():
                client = get_client()
                device = client.api.dcim.devices.get(name=device_name)
                if device:
                    return {
                        "device": device_name,
                        "region": device.site.region.name if device.site and device.site.region else None,
                        "site": device.site.name if device.site else None,
                        "rack": device.location.name if device.location else None,
                        "success": True
                    }
                return {"device": device_name, "error": "Device not found in NetBox", "success": False}
        except Exception as nb_err:
            logger.error(f"NetBox fallback error: {nb_err}")

        return {"device": device_name, "error": str(e), "success": False}


async def _get_netbox_ips(device_name: str = None) -> dict:
    """Get IP addresses from NetBox IPAM."""
    try:
        from config.netbox_client import get_client, is_netbox_available

        if not is_netbox_available():
            return {"error": "NetBox not available", "success": False}

        client = get_client()
        ips = client.get_ip_addresses(device_name)

        if device_name:
            return {
                "device": device_name,
                "ip_addresses": ips,
                "count": len(ips),
                "source": "netbox",
                "success": True
            }
        else:
            return {
                "ip_addresses": ips,
                "count": len(ips),
                "source": "netbox",
                "success": True
            }
    except Exception as e:
        logger.error(f"NetBox IP query error: {e}")
        return {"error": str(e), "success": False}


def execute_tool_sync(tool_name: str, tool_input: dict) -> dict:
    """Synchronous wrapper for tool execution."""
    from core.async_utils import run_sync
    return run_sync(execute_tool(tool_name, tool_input))
