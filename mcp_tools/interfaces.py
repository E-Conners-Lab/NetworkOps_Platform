"""
Interface operations: status, remediation, QoS.
"""
import json
import re

from config.devices import DEVICES
from core import log_event
from core.scrapli_manager import get_ios_xe_connection
from ._ops_helpers import is_cisco_device


async def get_interface_status(device_name: str, interface: str) -> str:
    """Get detailed status of a specific interface"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Interface status only supported for IOS-XE devices"})

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(f"show interface {interface}")
        output = response.result
    except Exception as e:
        return json.dumps({"error": "Connection failed", "details": str(e)})

    status = {
        "device": device_name,
        "interface": interface,
        "admin_status": "unknown",
        "line_protocol": "unknown",
        "ip_address": None,
        "errors": {"input": 0, "output": 0, "crc": 0}
    }

    first_line = output.split('\n')[0].lower()

    if "administratively down" in first_line:
        status["admin_status"] = "admin_down"
        status["line_protocol"] = "down"
    elif " is up" in first_line:
        status["admin_status"] = "up"
        if "line protocol is up" in first_line:
            status["line_protocol"] = "up"
        elif "line protocol is down" in first_line:
            status["line_protocol"] = "down"
    elif " is down" in first_line:
        status["admin_status"] = "down"
        status["line_protocol"] = "down"

    ip_match = re.search(r"Internet address is (\d+\.\d+\.\d+\.\d+/\d+)", output)
    if ip_match:
        status["ip_address"] = ip_match.group(1)

    input_err = re.search(r"(\d+) input errors", output)
    output_err = re.search(r"(\d+) output errors", output)
    crc_err = re.search(r"(\d+) CRC", output)

    if input_err:
        status["errors"]["input"] = int(input_err.group(1))
    if output_err:
        status["errors"]["output"] = int(output_err.group(1))
    if crc_err:
        status["errors"]["crc"] = int(crc_err.group(1))

    return json.dumps(status, indent=2)


async def remediate_interface(device_name: str, interface: str, action: str = "no_shutdown") -> str:
    """Remediate an interface issue. Actions: no_shutdown, shutdown, bounce"""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    valid_actions = ["no_shutdown", "shutdown", "bounce"]
    if action not in valid_actions:
        return json.dumps({"error": f"Invalid action. Must be one of: {valid_actions}"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Interface remediation only supported for IOS-XE devices"})

    if action == "no_shutdown":
        commands = [f"interface {interface}", "no shutdown"]
    elif action == "shutdown":
        commands = [f"interface {interface}", "shutdown"]
    else:  # bounce
        commands = [f"interface {interface}", "shutdown", "no shutdown"]

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_configs(commands)
            output = response.result
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": "Connection failed",
            "details": str(e)
        })

    # Verify the fix
    try:
        async with get_ios_xe_connection(device_name) as conn:
            verify_response = await conn.send_command(f"show interface {interface}")
            verify_output = verify_response.result

        first_line = verify_output.split('\n')[0].lower()
        if action == "no_shutdown":
            fixed = "administratively down" not in first_line
        elif action == "shutdown":
            fixed = "administratively down" in first_line
        else:
            fixed = "administratively down" not in first_line
    except Exception:
        fixed = False

    log_event("remediate", device_name, f"{action} on {interface}", "success" if fixed else "unverified", "admin")

    return json.dumps({
        "success": True,
        "device": device_name,
        "interface": interface,
        "action": action,
        "verified": fixed,
        "output": output
    }, indent=2)


async def get_qos_stats(device_name: str, interface: str = None) -> str:
    """Get QoS statistics including queue depths and drops."""
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "QoS stats only supported for Cisco devices"})

    try:
        async with get_ios_xe_connection(device_name) as conn:
            if interface:
                qos_output = await conn.send_command(f"show policy-map interface {interface}")
            else:
                qos_output = await conn.send_command("show policy-map interface")

            policy_output = await conn.send_command("show policy-map")

        result = {
            "status": "success",
            "device": device_name,
            "interfaces": {},
            "policies": [],
            "summary": {
                "total_interfaces_with_qos": 0,
                "total_drops": 0,
                "classes_with_drops": 0
            }
        }

        current_interface = None
        current_class = None

        for line in qos_output.result.splitlines():
            if "Service-policy" in line:
                policy_match = re.search(r'Service-policy\s+(input|output):\s+(\S+)', line)
                if policy_match and current_interface:
                    direction = policy_match.group(1)
                    policy_name = policy_match.group(2)
                    if current_interface not in result["interfaces"]:
                        result["interfaces"][current_interface] = {"input": None, "output": None, "classes": []}
                        result["summary"]["total_interfaces_with_qos"] += 1
                    result["interfaces"][current_interface][direction] = policy_name

            if re.match(r'^[A-Za-z]', line) and not line.startswith(" "):
                intf_match = re.match(r'^(\S+)', line)
                if intf_match:
                    current_interface = intf_match.group(1)

            class_match = re.search(r'Class-map:\s+(\S+)', line)
            if class_match and current_interface:
                current_class = class_match.group(1)

            if current_interface and current_class:
                drop_match = re.search(r'(\d+)\s+packets,\s+(\d+)\s+bytes.*drop', line, re.IGNORECASE)
                if drop_match:
                    drops = int(drop_match.group(1))
                    if drops > 0:
                        result["summary"]["total_drops"] += drops
                        result["summary"]["classes_with_drops"] += 1

        for line in policy_output.result.splitlines():
            policy_match = re.match(r'\s*Policy Map (\S+)', line)
            if policy_match:
                result["policies"].append({"name": policy_match.group(1), "classes": []})

            class_match = re.match(r'\s*Class (\S+)', line)
            if class_match and result["policies"]:
                result["policies"][-1]["classes"].append(class_match.group(1))

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


TOOLS = [
    {"fn": get_interface_status, "name": "get_interface_status", "category": "operations"},
    {"fn": remediate_interface, "name": "remediate_interface", "category": "operations"},
    {"fn": get_qos_stats, "name": "get_qos_stats", "category": "operations"},
]
