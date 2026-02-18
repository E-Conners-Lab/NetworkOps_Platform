"""
Session and security operations: active sessions, AAA, ACLs, logs.
"""
import json
import re
from core.timestamps import isonow

from config.devices import DEVICES
from core.scrapli_manager import get_ios_xe_connection, get_linux_connection
from ._ops_helpers import is_cisco_device


async def get_active_sessions(device_name: str = None) -> str:
    """
    Get active user sessions on device(s).

    Shows who is currently logged into devices via console, VTY, or SSH.

    Args:
        device_name: Specific device, or None for all Cisco devices

    Returns:
        JSON with active sessions per device
    """
    devices_to_check = [device_name] if device_name else [
        d for d in DEVICES.keys() if is_cisco_device(d)
    ]

    results = {
        "status": "success",
        "timestamp": isonow(),
        "devices_checked": len(devices_to_check),
        "results": {},
        "summary": {
            "total_sessions": 0,
            "devices_with_sessions": 0
        }
    }

    for dev_name in devices_to_check:
        if dev_name not in DEVICES:
            results["results"][dev_name] = {"error": "Device not found"}
            continue

        if not is_cisco_device(dev_name):
            results["results"][dev_name] = {"error": "Not a Cisco device"}
            continue

        try:
            async with get_ios_xe_connection(dev_name) as conn:
                # Get user sessions
                users_output = await conn.send_command("show users")
                ssh_output = await conn.send_command("show ssh")

            sessions = []

            # Parse show users output
            for line in users_output.result.splitlines():
                # Match lines like: *  0 con 0     admin          idle   00:00:00
                match = re.match(r'[\s\*]*(\d+)\s+(con|vty|aux)\s+(\d+)\s+(\S+)', line)
                if match:
                    sessions.append({
                        "line": f"{match.group(2)} {match.group(3)}",
                        "user": match.group(4),
                        "type": match.group(2).upper()
                    })

            # Parse show ssh for additional details
            ssh_sessions = []
            for line in ssh_output.result.splitlines():
                # Match: %No SSHv2 server connections running. OR session lines
                if "Connection" in line and "Version" in line:
                    continue  # Header
                match = re.match(r'\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', line)
                if match:
                    ssh_sessions.append({
                        "session": match.group(1),
                        "version": match.group(2),
                        "state": match.group(4),
                        "user": match.group(5) if len(match.groups()) > 4 else "unknown"
                    })

            results["results"][dev_name] = {
                "session_count": len(sessions),
                "sessions": sessions,
                "ssh_sessions": ssh_sessions
            }

            if sessions:
                results["summary"]["devices_with_sessions"] += 1
                results["summary"]["total_sessions"] += len(sessions)

        except Exception as e:
            results["results"][dev_name] = {"error": str(e)}

    return json.dumps(results, indent=2)


async def get_aaa_config(device_name: str) -> str:
    """
    Get AAA/TACACS/RADIUS configuration summary.

    Args:
        device_name: Device to check

    Returns:
        JSON with AAA configuration details
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "AAA config only supported for Cisco devices"})

    try:
        async with get_ios_xe_connection(device_name) as conn:
            config_output = await conn.send_command("show running-config | section aaa")
            tacacs_output = await conn.send_command("show tacacs")
            radius_output = await conn.send_command("show aaa servers")

        result = {
            "status": "success",
            "device": device_name,
            "aaa_enabled": "aaa new-model" in config_output.result,
            "config_sections": {},
            "tacacs_servers": [],
            "radius_servers": [],
            "authentication_methods": [],
            "authorization_methods": [],
            "accounting_methods": []
        }

        # Parse AAA config
        config = config_output.result

        # Find authentication methods
        for match in re.finditer(r'aaa authentication (\S+) (\S+) (.+)', config):
            result["authentication_methods"].append({
                "type": match.group(1),
                "list": match.group(2),
                "methods": match.group(3).strip()
            })

        # Find authorization methods
        for match in re.finditer(r'aaa authorization (\S+) (\S+) (.+)', config):
            result["authorization_methods"].append({
                "type": match.group(1),
                "list": match.group(2),
                "methods": match.group(3).strip()
            })

        # Find accounting methods
        for match in re.finditer(r'aaa accounting (\S+) (\S+) (.+)', config):
            result["accounting_methods"].append({
                "type": match.group(1),
                "list": match.group(2),
                "methods": match.group(3).strip()
            })

        # Parse TACACS servers
        for match in re.finditer(r'tacacs server (\S+)', config):
            result["tacacs_servers"].append(match.group(1))

        # Parse RADIUS servers
        for match in re.finditer(r'radius server (\S+)', config):
            result["radius_servers"].append(match.group(1))

        # Summary
        result["summary"] = {
            "aaa_model": "new-model" if result["aaa_enabled"] else "legacy",
            "tacacs_server_count": len(result["tacacs_servers"]),
            "radius_server_count": len(result["radius_servers"]),
            "auth_method_count": len(result["authentication_methods"])
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


async def acl_analysis(device_name: str, acl_name: str = None) -> str:
    """
    Analyze ACL rules on a device.

    Shows ACL summary, rule counts, and identifies potential issues
    like shadowed rules or overly permissive entries.

    Args:
        device_name: Device to analyze
        acl_name: Specific ACL name/number, or None for all ACLs

    Returns:
        JSON with ACL analysis
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "ACL analysis only supported for Cisco devices"})

    try:
        async with get_ios_xe_connection(device_name) as conn:
            if acl_name:
                acl_output = await conn.send_command(f"show access-lists {acl_name}")
            else:
                acl_output = await conn.send_command("show access-lists")

            # Get interface ACL assignments
            intf_output = await conn.send_command("show ip interface | include access list")

        result = {
            "status": "success",
            "device": device_name,
            "acls": {},
            "interface_assignments": [],
            "warnings": [],
            "summary": {
                "total_acls": 0,
                "total_rules": 0,
                "permit_rules": 0,
                "deny_rules": 0
            }
        }

        current_acl = None
        current_rules = []

        for line in acl_output.result.splitlines():
            # Match ACL header: "Standard IP access list 10" or "Extended IP access list BLOCK_TELNET"
            acl_match = re.match(r'(Standard|Extended) IP access list (\S+)', line)
            if acl_match:
                # Save previous ACL
                if current_acl:
                    result["acls"][current_acl["name"]] = current_acl
                    result["acls"][current_acl["name"]]["rules"] = current_rules

                current_acl = {
                    "name": acl_match.group(2),
                    "type": acl_match.group(1).lower(),
                    "rule_count": 0,
                    "permit_count": 0,
                    "deny_count": 0
                }
                current_rules = []
                result["summary"]["total_acls"] += 1
                continue

            # Match ACL rules
            if current_acl:
                rule_match = re.match(r'\s*(\d+)?\s*(permit|deny)\s+(.+)', line)
                if rule_match:
                    seq = rule_match.group(1) or str(len(current_rules) + 1)
                    action = rule_match.group(2)
                    condition = rule_match.group(3).strip()

                    rule = {
                        "sequence": seq,
                        "action": action,
                        "condition": condition
                    }
                    current_rules.append(rule)

                    current_acl["rule_count"] += 1
                    result["summary"]["total_rules"] += 1

                    if action == "permit":
                        current_acl["permit_count"] += 1
                        result["summary"]["permit_rules"] += 1

                        # Check for overly permissive rules
                        if "any any" in condition or condition.strip() == "ip any any":
                            result["warnings"].append({
                                "acl": current_acl["name"],
                                "rule": seq,
                                "warning": "Overly permissive: permit any any",
                                "severity": "high"
                            })
                    else:
                        current_acl["deny_count"] += 1
                        result["summary"]["deny_rules"] += 1

        # Save last ACL
        if current_acl:
            result["acls"][current_acl["name"]] = current_acl
            result["acls"][current_acl["name"]]["rules"] = current_rules

        # Parse interface assignments
        for line in intf_output.result.splitlines():
            if "access list" in line.lower():
                result["interface_assignments"].append(line.strip())

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


async def get_logs(device_name: str, lines: int = 50, severity: str = None) -> str:
    """
    Get device logs/syslog buffer.

    Args:
        device_name: Device to get logs from
        lines: Number of log lines to retrieve (default 50)
        severity: Filter by severity (emergencies, alerts, critical, errors, warnings, notifications, informational, debugging)

    Returns:
        JSON with parsed log entries
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    device = DEVICES[device_name]
    device_type = device.get("device_type", "")

    if device_type == "cisco_xe":
        cmd = "show logging"
    elif device_type == "linux":
        cmd = f"dmesg | tail -{lines} 2>/dev/null || journalctl -n {lines} 2>/dev/null || tail -{lines} /var/log/syslog 2>/dev/null"
    else:
        return json.dumps({"error": f"Logs not supported for device type: {device_type}"})

    try:
        if device_type == "cisco_xe":
            async with get_ios_xe_connection(device_name) as conn:
                response = await conn.send_command(cmd)
                output = response.result
        elif device_type == "linux":
            async with get_linux_connection(device_name) as conn:
                response = await conn.send_command(cmd)
                output = response.result

        # Parse Cisco logs
        log_entries = []
        severity_map = {
            '0': 'emergencies', '1': 'alerts', '2': 'critical', '3': 'errors',
            '4': 'warnings', '5': 'notifications', '6': 'informational', '7': 'debugging'
        }

        if device_type == "cisco_xe":
            # Parse Cisco syslog format: "Dec 27 18:30:45.123 EST: %SYS-5-CONFIG_I: ..."
            for line in output.splitlines():
                log_match = re.match(
                    r'[\*\s]*(\w+\s+\d+\s+[\d:\.]+(?:\s+\w+)?):\s+%(\w+)-(\d)-(\w+):\s*(.*)',
                    line
                )
                if log_match:
                    entry_severity = severity_map.get(log_match.group(3), log_match.group(3))
                    if severity and entry_severity != severity:
                        continue
                    log_entries.append({
                        "timestamp": log_match.group(1),
                        "facility": log_match.group(2),
                        "severity": entry_severity,
                        "mnemonic": log_match.group(4),
                        "message": log_match.group(5)
                    })
        else:
            # Simple line-by-line for Linux
            for line in output.splitlines()[-lines:]:
                if line.strip():
                    log_entries.append({"message": line.strip()})

        # Count by severity
        severity_counts = {}
        for entry in log_entries:
            sev = entry.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return json.dumps({
            "device": device_name,
            "filter": {"lines": lines, "severity": severity},
            "total_entries": len(log_entries),
            "by_severity": severity_counts,
            "entries": log_entries[-lines:]  # Limit to requested lines
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "device": device_name}, indent=2)


TOOLS = [
    {"fn": get_active_sessions, "name": "get_active_sessions", "category": "operations"},
    {"fn": get_aaa_config, "name": "get_aaa_config", "category": "operations"},
    {"fn": acl_analysis, "name": "acl_analysis", "category": "operations"},
    {"fn": get_logs, "name": "get_logs", "category": "operations"},
]
