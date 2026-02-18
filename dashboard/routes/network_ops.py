"""
Network Operations API Routes.

Command execution, ping, BGP, and OSPF endpoints for network devices.
"""

import ipaddress
import os
import re
import logging

from flask import Blueprint, jsonify, request, g
from netmiko import ConnectHandler
from core.errors import safe_error_response, NotFoundError, ValidationError
from dashboard.auth import jwt_required

logger = logging.getLogger(__name__)

# BGP AS numbers — configurable for portability
_LOCAL_AS = {
    "eveng": os.getenv("BGP_AS_EVENG", "65000"),
    "containerlab": os.getenv("BGP_AS_CONTAINERLAB", "65100"),
}


# =============================================================================
# Input Validation Helpers
# =============================================================================

# Hostname regex: RFC 1123 compliant
# - Labels: alphanumeric, can contain hyphens (not at start/end)
# - Max 253 chars total, each label max 63 chars
_HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$'
)


def validate_ip_or_hostname(value: str) -> tuple[bool, str]:
    """
    Validate that a string is a valid IPv4/IPv6 address or hostname.

    Args:
        value: The string to validate

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is empty string
    """
    if not value:
        return False, "Value cannot be empty"

    if not isinstance(value, str):
        return False, "Value must be a string"

    # Reject shell metacharacters regardless of format
    dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in value:
            return False, f"Invalid character in value: {repr(char)}"

    # Try to parse as IP address first
    try:
        ipaddress.ip_address(value)
        return True, ""
    except ValueError:
        pass

    # Try to parse as IP network (e.g., 10.0.0.0/24)
    try:
        ipaddress.ip_network(value, strict=False)
        return True, ""
    except ValueError:
        pass

    # Validate as hostname
    if len(value) > 253:
        return False, "Hostname too long (max 253 characters)"

    if _HOSTNAME_PATTERN.match(value):
        return True, ""

    return False, "Invalid IP address or hostname format"


def validate_ping_count(value) -> tuple[bool, int, str]:
    """
    Validate ping count parameter.

    Args:
        value: The count value (may be int, str, or other)

    Returns:
        Tuple of (is_valid, sanitized_value, error_message)
        If valid, sanitized_value is the integer count (1-10)
    """
    try:
        count = int(value)
    except (TypeError, ValueError):
        return False, 0, "Count must be an integer"

    if count < 1:
        return False, 0, "Count must be at least 1"

    if count > 10:
        return False, 0, "Count must be at most 10"

    return True, count, ""

network_ops_bp = Blueprint('network_ops', __name__)


# Loopback addresses (imported from centralized map)
from config.devices import DEVICES, DEVICE_HOSTS, ROUTER_LOOPBACKS, SWITCH_LOOPBACKS
from config.devices import is_containerlab_device

# Containerlab device IPs reachable from EVE-NG routers
# Note: spine1, server1, server2 are on internal containerlab networks (10.200.x, 10.100.x)
# and are NOT routable from EVE-NG. Only devices on Docker bridge (172.20.20.x) are reachable.
# Loopback-based routing requires complex cross-network routing between EVE-NG and Docker.
CONTAINERLAB_LOOPBACKS = {
    name: DEVICE_HOSTS[name]
    for name in DEVICE_HOSTS
    if is_containerlab_device(name) and name not in ("server1", "server2", "spine1")
}

ROUTER_LAN_IPS = {
    name: d["lan_ip"]
    for name, d in DEVICES.items()
    if d.get("lan_ip")
}

ALL_LOOPBACKS = {**ROUTER_LOOPBACKS, **SWITCH_LOOPBACKS, **CONTAINERLAB_LOOPBACKS}
LOOPBACK_TO_ROUTER = {v: k for k, v in ROUTER_LOOPBACKS.items()}
LOOPBACK_TO_DEVICE = {v: k for k, v in ALL_LOOPBACKS.items()}


def _get_devices():
    """Get devices dictionary from config."""
    from config.devices import DEVICES
    return DEVICES


def _is_containerlab_device(device_name):
    """Check if device is a containerlab device."""
    from dashboard.api_server import is_containerlab_device
    return is_containerlab_device(device_name)


def _is_linux_device(device_name):
    """Check if device is a Linux host."""
    from dashboard.api_server import is_linux_device
    return is_linux_device(device_name)


def _run_containerlab_command(device_name, command):
    """Run command on containerlab device."""
    from dashboard.api_server import run_containerlab_command
    return run_containerlab_command(device_name, command)


def _run_containerlab_ping(device_name, target_ip):
    """Run ping from containerlab device and parse results."""
    import re

    # Validate target_ip to prevent shell injection
    is_valid, error_msg = validate_ip_or_hostname(target_ip)
    if not is_valid:
        logger.warning(f"Invalid target_ip for containerlab ping: {target_ip} ({error_msg})")
        return {"success_rate": "0%", "avg_latency": 0, "error": error_msg}

    try:
        from core.containerlab import run_command

        # Run ping command (2 packets, short timeout)
        logger.info(f"Running containerlab ping from {device_name} to {target_ip}")
        cmd = f"ping -c 2 -W 2 {target_ip}"
        output = run_command(device_name, cmd)
        logger.debug(f"Ping output: {output[:200] if output else 'empty'}")

        # Parse ping output
        success_rate = "0%"
        avg_latency = 0

        # Look for "X packets transmitted, Y received" pattern
        match = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received', output)
        if match:
            transmitted = int(match.group(1))
            received = int(match.group(2))
            if transmitted > 0:
                success_rate = f"{int(received / transmitted * 100)}%"

        # Look for avg latency in "min/avg/max" pattern
        match = re.search(r'min/avg/max(?:/mdev)? = [\d.]+/([\d.]+)/', output)
        if match:
            avg_latency = float(match.group(1))

        return {"success_rate": success_rate, "avg_latency": avg_latency}
    except Exception as e:
        logger.exception(f"Exception in containerlab ping: {e}")
        return {"success_rate": "0%", "avg_latency": 0}


def _validate_command(command, permissions):
    """Validate command is allowed."""
    from dashboard.api_server import validate_command
    return validate_command(command, permissions)


def _is_config_command(command):
    """Check if command changes config."""
    from dashboard.api_server import is_config_command
    return is_config_command(command)


def _log_event(action, device, detail, status, username):
    """Log an event."""
    from dashboard.api_server import log_event
    log_event(action, device=device, details=detail, status=status, user=username)


def _invalidate_device_cache(device_name, is_config=False):
    """Invalidate device cache."""
    from dashboard.api_server import invalidate_device_cache
    invalidate_device_cache(device_name, is_config)


# =============================================================================
# Command Execution
# =============================================================================

@network_ops_bp.route('/api/command', methods=['POST'])
@jwt_required
def run_command():
    """Execute command on a network device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        return _run_command_demo()

    DEVICES = _get_devices()
    data = request.get_json()

    if not data or not isinstance(data, dict):
        raise ValidationError("No data provided")

    device_name = data.get('device')
    command = data.get('command')
    username = g.current_user  # Get username from JWT token
    permissions = g.current_permissions  # Get permissions from JWT token

    # Type validation
    if not isinstance(device_name, str) or not isinstance(command, str):
        raise ValidationError("Device and command must be strings")

    if not device_name or not command:
        raise ValidationError("Missing device or command")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    is_valid, error_msg = _validate_command(command, permissions)
    if not is_valid:
        _log_event("command_blocked", device_name, f"Blocked: {command} ({error_msg})", "forbidden", username)
        return jsonify({"error": error_msg, "status": "forbidden"}), 403

    device = DEVICES[device_name]

    if _is_containerlab_device(device_name):
        try:
            output = _run_containerlab_command(device_name, command)
            _log_event("command", device_name, f"Executed: {command}", "success", username)

            # Invalidate cache after successful command
            _invalidate_device_cache(device_name, is_config=_is_config_command(command))

            return jsonify({
                "device": device_name,
                "command": command,
                "output": output,
                "status": "success"
            })
        except Exception as e:
            _log_event("command", device_name, f"Failed: {command}", "error", username)
            return safe_error_response(e, f"execute command on {device_name}")

    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command(command, read_timeout=60)
        finally:
            connection.disconnect()

        _log_event("command", device_name, f"Executed: {command}", "success", username)

        # Invalidate cache after successful command
        _invalidate_device_cache(device_name, is_config=_is_config_command(command))

        return jsonify({
            "device": device_name,
            "command": command,
            "output": output,
            "status": "success"
        })
    except Exception as e:
        _log_event("command", device_name, f"Failed: {command}", "error", username)
        return safe_error_response(e, f"execute command on {device_name}")


# =============================================================================
# Ping Operations
# =============================================================================

@network_ops_bp.route('/api/ping', methods=['POST'])
@jwt_required
def run_ping():
    """Ping from a device to a destination."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        data = request.get_json() or {}
        device_name = data.get('device', 'R1')
        destination = data.get('destination', '198.51.100.1')
        count = data.get('count', 5)
        import random
        latency = round(random.uniform(1.0, 15.0), 1)
        return jsonify({
            "device": device_name,
            "destination": destination,
            "count": count,
            "output": f"Sending {count}, 100-byte ICMP Echos to {destination}, timeout is 2 seconds:\n{'!' * count}\nSuccess rate is 100 percent ({count}/{count}), round-trip min/avg/max = {latency}/{latency + 1.2}/{latency + 3.5} ms",
            "success_rate": "100%",
            "status": "success"
        })

    DEVICES = _get_devices()
    data = request.get_json()

    if not data:
        raise ValidationError("No data provided")

    device_name = data.get('device')
    destination = data.get('destination')
    count = data.get('count', 5)
    role = g.current_role  # Get role from JWT token

    if not device_name or not destination:
        raise ValidationError("Missing device or destination")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    # Validate destination to prevent command injection
    is_valid_dest, dest_error = validate_ip_or_hostname(destination)
    if not is_valid_dest:
        raise ValidationError(f"Invalid destination: {dest_error}")

    # Validate count parameter (must be integer 1-10)
    is_valid_count, count, count_error = validate_ping_count(count)
    if not is_valid_count:
        raise ValidationError(f"Invalid count: {count_error}")

    ping_command = f"ping {destination} repeat {count}"

    device = DEVICES[device_name]
    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command(ping_command, read_timeout=60)
        finally:
            connection.disconnect()

        success_rate = "unknown"
        match = re.search(r'Success rate is (\d+) percent', output)
        if match:
            success_rate = f"{match.group(1)}%"

        _log_event("ping", device_name, f"Ping to {destination}: {success_rate}", "success", g.current_user)
        return jsonify({
            "device": device_name,
            "destination": destination,
            "count": count,
            "output": output,
            "success_rate": success_rate,
            "status": "success"
        })
    except Exception as e:
        _log_event("ping", device_name, f"Ping to {destination} failed", "error", g.current_user)
        return safe_error_response(e, f"ping from {device_name} to {destination}")


def _run_command_demo():
    """Return simulated CLI output for demo mode."""
    from core.demo.fixtures import DEMO_DEVICES, DEMO_INTERFACES

    data = request.get_json()
    if not data or not isinstance(data, dict):
        raise ValidationError("No data provided")
    device_name = data.get('device')
    command = data.get('command', '')
    if not device_name or not command:
        raise ValidationError("Missing device or command")
    if device_name not in DEMO_DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    dev = DEMO_DEVICES[device_name]
    cmd_lower = command.lower().strip()

    if 'show ip interface brief' in cmd_lower:
        lines = ["Interface                  IP-Address      OK? Method Status                Protocol"]
        loopback = dev.get("loopback", "unassigned")
        lines.append(f"{'Loopback0':<27}{loopback:<16}YES manual up                    up")
        for intf in DEMO_INTERFACES.get(device_name, []):
            ip = "unassigned"
            status = intf["status"]
            proto = status
            lines.append(f"{intf['name']:<27}{ip:<16}YES unset  {'up':<22}{proto}")
        output = "\n".join(lines)
    elif 'show version' in cmd_lower:
        platform = dev.get("platform", "C8000V")
        output = (
            f"Cisco IOS XE Software, Version 17.13.01a\n"
            f"{platform} Software ({platform}-UNIVERSALK9-M), Version 17.13.1a\n"
            f"Uptime: 1 day, 2 hours, 15 minutes\n"
            f"System image file is \"bootflash:packages.conf\"\n"
            f"{platform} platform with 8388608K bytes of memory."
        )
    elif 'show ip route' in cmd_lower:
        output = (
            f"Codes: C - connected, S - static, O - OSPF, B - BGP\n"
            f"Gateway of last resort is not set\n\n"
            f"      198.51.100.0/32 is subnetted, 4 subnets\n"
            f"C        {dev.get('loopback', '198.51.100.1')}/32 is directly connected, Loopback0\n"
            f"O        198.51.100.0/24 [110/2] via 10.12.0.2, GigabitEthernet2\n"
            f"B        10.255.0.0/24 [200/0] via 198.51.100.3"
        )
    elif 'show run' in cmd_lower:
        output = "% Demo mode: configuration commands are not available"
    else:
        output = f"% Demo mode: simulated output not available for '{command}'"

    return jsonify({
        "device": device_name,
        "command": command,
        "output": output,
        "status": "success",
    })


def _ping_sweep_demo():
    """Return simulated ping sweep results for demo mode."""
    import random
    from core.demo.fixtures import DEMO_DEVICES

    data = request.get_json()
    if not data:
        raise ValidationError("No data provided")
    device_name = data.get('device')
    if not device_name or device_name not in DEMO_DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    # Build targets: all devices with a loopback
    targets = {
        name: dev["loopback"]
        for name, dev in DEMO_DEVICES.items()
        if "loopback" in dev
    }

    results = []
    for target_name, target_ip in targets.items():
        if target_name == device_name:
            results.append({
                "target": target_name,
                "target_ip": target_ip,
                "success_rate": "100%",
                "avg_latency": 0,
                "status": "self",
            })
        else:
            latency = random.randint(1, 4)
            results.append({
                "target": target_name,
                "target_ip": target_ip,
                "success_rate": "100%",
                "avg_latency": latency,
                "status": "success",
            })

    return jsonify({"device": device_name, "results": results, "status": "success"})


@network_ops_bp.route('/api/ping-sweep', methods=['POST'])
@jwt_required
def ping_sweep():
    """Ping all reachable targets from a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        return _ping_sweep_demo()

    DEVICES = _get_devices()
    data = request.get_json()

    if not data:
        raise ValidationError("No data provided")

    device_name = data.get('device')
    role = g.current_role  # Get role from JWT token

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]
    results = []

    is_containerlab = _is_containerlab_device(device_name)
    is_source_switch = device_name in SWITCH_LOOPBACKS
    is_source_containerlab = device_name in CONTAINERLAB_LOOPBACKS
    logger.info(f"Ping sweep: device={device_name}, is_containerlab={is_containerlab}, is_source_containerlab={is_source_containerlab}")

    if is_source_switch:
        targets = {**ROUTER_LAN_IPS, **SWITCH_LOOPBACKS}
    elif is_source_containerlab:
        # Use loopbacks for EVE-NG routers (reachable via eBGP through edge1)
        targets = {**ROUTER_LOOPBACKS, **CONTAINERLAB_LOOPBACKS}
    else:
        # Routers ping all loopbacks including containerlab
        # Note: Only R3 has routes to containerlab via BGP
        targets = {**ROUTER_LOOPBACKS, **SWITCH_LOOPBACKS, **CONTAINERLAB_LOOPBACKS}

    try:
        if is_containerlab:
            for target_name, target_ip in targets.items():
                if target_name == device_name:
                    results.append({
                        "target": target_name,
                        "target_ip": target_ip,
                        "success_rate": "100%",
                        "avg_latency": 0,
                        "status": "self"
                    })
                    continue

                ping_result = _run_containerlab_ping(device_name, target_ip)
                results.append({
                    "target": target_name,
                    "target_ip": target_ip,
                    "success_rate": ping_result["success_rate"],
                    "avg_latency": ping_result["avg_latency"],
                    "status": "success" if ping_result["success_rate"] != "0%" else "failed"
                })

            return jsonify({
                "device": device_name,
                "results": results,
                "status": "success"
            })

        connection = ConnectHandler(**device)
        try:
            for target_name, target_ip in targets.items():
                if target_name == device_name:
                    results.append({
                        "target": target_name,
                        "target_ip": target_ip,
                        "success_rate": "100%",
                        "avg_latency": 0,
                        "status": "self"
                    })
                    continue

                if is_source_switch:
                    source_ip = SWITCH_LOOPBACKS[device_name]
                    ping_cmd = f"ping {target_ip} source {source_ip} repeat 3 timeout 2"
                else:
                    ping_cmd = f"ping {target_ip} repeat 3 timeout 2"
                output = connection.send_command(ping_cmd, read_timeout=15)

                success_rate = "0%"
                avg_latency = 0

                rate_match = re.search(r'Success rate is (\d+) percent', output)
                if rate_match:
                    success_rate = f"{rate_match.group(1)}%"

                latency_match = re.search(r'min/avg/max = \d+/(\d+)/\d+', output)
                if latency_match:
                    avg_latency = int(latency_match.group(1))

                results.append({
                    "target": target_name,
                    "target_ip": target_ip,
                    "success_rate": success_rate,
                    "avg_latency": avg_latency,
                    "status": "success" if success_rate != "0%" else "failed"
                })
        finally:
            connection.disconnect()

        return jsonify({
            "device": device_name,
            "results": results,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"ping sweep from {device_name}")


# =============================================================================
# BGP Operations
# =============================================================================

@network_ops_bp.route('/api/bgp-summary')
@jwt_required
def get_bgp_summary():
    """Get BGP neighbor summary for a device."""
    from core.demo import DEMO_MODE
    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    if DEMO_MODE:
        from core.demo.fixtures import DEMO_BGP_PEERS
        peers = DEMO_BGP_PEERS.get(device_name, [])
        neighbors = [
            {
                "neighbor": p["neighbor"],
                "remote_as": str(p["remote_as"]),
                "state": p["state"],
                "prefixes": p.get("prefixes_received", 0),
                "peer_type": "iBGP" if p["remote_as"] == 65000 else "eBGP",
                "uptime": p.get("uptime", ""),
            }
            for p in peers
        ]
        return jsonify({"status": "success", "device": device_name, "neighbors": neighbors})

    device = DEVICES[device_name]

    if _is_containerlab_device(device_name) and device.get('device_type') == 'containerlab_frr':
        try:
            output = _run_containerlab_command(device_name, "show ip bgp summary")

            neighbors = []
            lines = output.split('\n')
            in_neighbor_section = False

            for line in lines:
                if 'Neighbor' in line and 'AS' in line:
                    in_neighbor_section = True
                    continue

                if in_neighbor_section and line.strip():
                    parts = line.split()
                    if len(parts) >= 10 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        neighbor_ip = parts[0]
                        remote_as = parts[2]
                        state_or_pfx = parts[9]

                        if state_or_pfx.isdigit():
                            state = "Established"
                            prefixes = int(state_or_pfx)
                        else:
                            state = state_or_pfx
                            prefixes = 0

                        peer_type = "iBGP" if remote_as == _LOCAL_AS["containerlab"] else "eBGP"

                        neighbors.append({
                            "neighbor": neighbor_ip,
                            "remote_as": remote_as,
                            "state": state,
                            "prefixes": prefixes,
                            "peer_type": peer_type,
                            "neighbor_name": LOOPBACK_TO_DEVICE.get(neighbor_ip)
                        })

            return jsonify({
                "device": device_name,
                "neighbors": neighbors,
                "status": "success"
            })
        except Exception as e:
            return safe_error_response(e, f"get BGP summary for {device_name}")

    if _is_containerlab_device(device_name):
        return jsonify({
            "device": device_name,
            "neighbors": [],
            "message": "BGP not configured on this device",
            "status": "success"
        })

    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command("show ip bgp summary")
        finally:
            connection.disconnect()

        neighbors = []
        lines = output.split('\n')
        in_neighbor_section = False

        for line in lines:
            if 'Neighbor' in line and 'AS' in line:
                in_neighbor_section = True
                continue

            if in_neighbor_section and line.strip():
                parts = line.split()
                if len(parts) >= 9 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    neighbor_ip = parts[0]
                    remote_as = parts[2]
                    state_or_pfx = parts[-1]

                    if state_or_pfx.isdigit():
                        state = "Established"
                        prefixes = int(state_or_pfx)
                    else:
                        state = state_or_pfx
                        prefixes = 0

                    peer_type = "iBGP" if remote_as == _LOCAL_AS["eveng"] else "eBGP"

                    neighbors.append({
                        "neighbor": neighbor_ip,
                        "remote_as": remote_as,
                        "state": state,
                        "prefixes": prefixes,
                        "peer_type": peer_type,
                        "neighbor_name": LOOPBACK_TO_DEVICE.get(neighbor_ip)
                    })

        return jsonify({
            "device": device_name,
            "neighbors": neighbors,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"get BGP summary for {device_name}")


# =============================================================================
# OSPF Operations
# =============================================================================

@network_ops_bp.route('/api/ospf-neighbors')
@jwt_required
def get_ospf_neighbors():
    """Get OSPF neighbor adjacencies for a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_OSPF_ADJACENCIES, DEMO_DEVICES
        device_name = request.args.get('device')
        if not device_name:
            raise ValidationError("Missing device parameter")
        adjacencies = DEMO_OSPF_ADJACENCIES.get(device_name, [])
        neighbors = []
        for adj in adjacencies:
            neighbors.append({
                "neighbor_id": adj["neighbor_id"],
                "priority": 1,
                "state": adj["state"],
                "uptime": "1d02h",
                "address": adj["neighbor_id"],
                "interface": adj["interface"],
            })
        return jsonify({
            "device": device_name,
            "neighbors": neighbors,
            "status": "success"
        })

    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]

    # Only Cisco routers support OSPF in this lab
    if _is_containerlab_device(device_name) or _is_linux_device(device_name):
        return jsonify({
            "device": device_name,
            "neighbors": [],
            "message": "OSPF not supported on this device type",
            "status": "success"
        })

    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command("show ip ospf neighbor")
        finally:
            connection.disconnect()

        neighbors = []
        for line in output.split('\n'):
            if not line.strip() or 'Neighbor ID' in line:
                continue
            parts = line.split()
            if len(parts) >= 6 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                neighbor_id = parts[0]
                priority = int(parts[1]) if parts[1].isdigit() else 0
                state_field = parts[2]
                state = state_field.split('/')[0]
                address = parts[4] if len(parts) > 4 else ''
                interface = parts[5] if len(parts) > 5 else ''
                dead_time = parts[3] if len(parts) > 3 else ''

                neighbors.append({
                    "neighbor_id": neighbor_id,
                    "priority": priority,
                    "state": state,
                    "uptime": dead_time,
                    "address": address,
                    "interface": interface
                })

        return jsonify({
            "device": device_name,
            "neighbors": neighbors,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"get OSPF neighbors for {device_name}")


@network_ops_bp.route('/api/ospf-interfaces')
@jwt_required
def get_ospf_interfaces():
    """Get OSPF interface configuration for a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_OSPF_ADJACENCIES
        device_name = request.args.get('device')
        if not device_name:
            raise ValidationError("Missing device parameter")
        adjacencies = DEMO_OSPF_ADJACENCIES.get(device_name, [])
        interfaces = [
            {
                "name": adj["interface"],
                "process_id": 1,
                "area": 0,
                "ip_address": adj["neighbor_id"],
                "cost": 1,
                "state": "P2P",
                "neighbors": 1,
                "neighbors_full": 1,
            }
            for adj in adjacencies
        ]
        return jsonify({
            "device": device_name,
            "interfaces": interfaces,
            "status": "success"
        })

    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]

    if _is_containerlab_device(device_name) or _is_linux_device(device_name):
        return jsonify({
            "device": device_name,
            "interfaces": [],
            "message": "OSPF not supported on this device type",
            "status": "success"
        })

    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command("show ip ospf interface brief")
        finally:
            connection.disconnect()

        interfaces = []
        for line in output.split('\n'):
            if not line.strip() or 'Interface' in line:
                continue
            parts = line.split()
            if len(parts) >= 7:
                name = parts[0]
                try:
                    process_id = int(parts[1])
                except (ValueError, IndexError):
                    process_id = 0
                try:
                    area = int(parts[2])
                except (ValueError, IndexError):
                    area = 0
                ip_addr = parts[3] if len(parts) > 3 else ''
                try:
                    cost = int(parts[4])
                except (ValueError, IndexError):
                    cost = 0
                state = parts[5] if len(parts) > 5 else ''
                nbrs = parts[6] if len(parts) > 6 else '0/0'
                nbrs_parts = nbrs.split('/')
                neighbors_full = int(nbrs_parts[0]) if nbrs_parts[0].isdigit() else 0
                neighbors = int(nbrs_parts[1]) if len(nbrs_parts) > 1 and nbrs_parts[1].isdigit() else 0

                interfaces.append({
                    "name": name,
                    "process_id": process_id,
                    "area": area,
                    "ip_address": ip_addr,
                    "cost": cost,
                    "state": state,
                    "neighbors": neighbors,
                    "neighbors_full": neighbors_full
                })

        return jsonify({
            "device": device_name,
            "interfaces": interfaces,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"get OSPF interfaces for {device_name}")


@network_ops_bp.route('/api/ospf-routes')
@jwt_required
def get_ospf_routes():
    """Get OSPF routes for a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_DEVICES
        device_name = request.args.get('device')
        if not device_name:
            raise ValidationError("Missing device parameter")
        routes = []
        for name, dev in DEMO_DEVICES.items():
            if name == device_name or "loopback" not in dev:
                continue
            if dev.get("device_type") != "cisco_xe":
                continue
            routes.append({
                "prefix": f"{dev['loopback']}/32",
                "route_type": "O",
                "admin_distance": 110,
                "metric": 2,
                "next_hop": dev.get("lan_ip", dev["loopback"]),
                "age": "1d02h",
                "interface": "GigabitEthernet2",
            })
        return jsonify({
            "device": device_name,
            "routes": routes,
            "status": "success"
        })

    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]

    if _is_containerlab_device(device_name) or _is_linux_device(device_name):
        return jsonify({
            "device": device_name,
            "routes": [],
            "message": "OSPF not supported on this device type",
            "status": "success"
        })

    try:
        connection = ConnectHandler(**device)
        try:
            output = connection.send_command("show ip route ospf")
        finally:
            connection.disconnect()

        routes = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            match = re.match(r'^(O\s*(?:IA|E1|E2)?)\s+(\d+\.\d+\.\d+\.\d+/?\d*)\s+\[(\d+)/(\d+)\]\s+via\s+(\d+\.\d+\.\d+\.\d+),?\s*(\S*),?\s*(\S*)', line)
            if match:
                route_type = match.group(1).strip()
                prefix = match.group(2)
                admin_distance = int(match.group(3))
                metric = int(match.group(4))
                next_hop = match.group(5)
                age = match.group(6) if match.group(6) else ''
                interface = match.group(7) if match.group(7) else ''

                routes.append({
                    "prefix": prefix,
                    "route_type": route_type,
                    "admin_distance": admin_distance,
                    "metric": metric,
                    "next_hop": next_hop,
                    "age": age,
                    "interface": interface
                })

        return jsonify({
            "device": device_name,
            "routes": routes,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"get OSPF routes for {device_name}")


@network_ops_bp.route('/api/ospf-status')
@jwt_required
def get_ospf_status():
    """Get OSPF status for all Cisco routers (for overlay visualization)."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_OSPF_ADJACENCIES, DEMO_DEVICES
        devices = {}
        for name, adjs in DEMO_OSPF_ADJACENCIES.items():
            devices[name] = {
                "status": "success",
                "router_id": DEMO_DEVICES[name].get("loopback", ""),
                "neighbors": adjs,
                "interfaces": [
                    {
                        "name": a["interface"],
                        "area": "0.0.0.0",  # nosec B104 — OSPF area ID, not a bind address
                        "state": "P2P" if "Gig" in a["interface"] else "LOOP",
                        "cost": 1,
                        "network_type": "POINT_TO_POINT",
                    }
                    for a in adjs
                ],
            }
        areas = {"0.0.0.0": list(DEMO_OSPF_ADJACENCIES.keys())}  # nosec B104 — OSPF area ID
        # Map loopback IPs (router IDs) to device names for frontend resolution
        router_id_map = {
            dev.get("loopback", ""): name
            for name, dev in DEMO_DEVICES.items()
            if "loopback" in dev and name in DEMO_OSPF_ADJACENCIES
        }
        return jsonify({
            "status": "success",
            "devices": devices,
            "areas": areas,
            "router_id_map": router_id_map,
        })

    from concurrent.futures import ThreadPoolExecutor, as_completed
    DEVICES = _get_devices()

    # Only Cisco routers run OSPF
    ospf_routers = [name for name, dev in DEVICES.items()
                    if dev.get('device_type') == 'cisco_xe'
                    and not name.startswith('Switch')]

    results = {}

    def fetch_ospf_data(device_name):
        device = DEVICES[device_name]
        try:
            connection = ConnectHandler(**device)

            # Get neighbors
            neighbor_output = connection.send_command("show ip ospf neighbor")
            neighbors = []
            for line in neighbor_output.split('\n'):
                if not line.strip() or 'Neighbor ID' in line:
                    continue
                parts = line.split()
                if len(parts) >= 6 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    neighbors.append({
                        "neighbor_id": parts[0],
                        "state": parts[2].split('/')[0],
                        "interface": parts[5] if len(parts) > 5 else ''
                    })

            # Get router-id from "Routing Process "ospf X" with ID x.x.x.x"
            router_id = None
            rid_output = connection.send_command("show ip ospf | include with ID")
            rid_match = re.search(r'with ID\s+([\d.]+)', rid_output)
            if rid_match:
                router_id = rid_match.group(1)

            # Get interfaces with areas and costs
            intf_output = connection.send_command("show ip ospf interface brief")
            interfaces = []
            for line in intf_output.split('\n'):
                if not line.strip() or 'Interface' in line:
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        area = int(parts[2])
                    except (ValueError, IndexError):
                        area = 0
                    try:
                        cost = int(parts[4])
                    except (ValueError, IndexError):
                        cost = 1
                    interfaces.append({
                        "name": parts[0],
                        "area": area,
                        "cost": cost,
                        "state": parts[5] if len(parts) > 5 else 'UNKNOWN'
                    })

            connection.disconnect()

            return device_name, {
                "neighbors": neighbors,
                "interfaces": interfaces,
                "router_id": router_id,
                "status": "success"
            }
        except Exception as e:
            logger.exception(f"Failed to fetch OSPF data from {device_name}")
            return device_name, {
                "neighbors": [],
                "interfaces": [],
                "error": "Failed to fetch OSPF data",
                "status": "error"
            }

    # Fetch from all routers in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fetch_ospf_data, name): name for name in ospf_routers}
        for future in as_completed(futures):
            device_name, data = future.result()
            results[device_name] = data

    # Build area mapping (which devices are in which area)
    area_map = {}  # area_id -> list of devices
    link_costs = {}  # "device1-device2" -> cost

    for device_name, data in results.items():
        for intf in data.get("interfaces", []):
            area = intf.get("area", 0)
            if area not in area_map:
                area_map[area] = set()
            area_map[area].add(device_name)

            # Map interface costs
            intf_name = intf.get("name", "")
            cost = intf.get("cost", 1)
            # Store cost keyed by device+interface
            link_costs[f"{device_name}:{intf_name}"] = cost

    # Convert sets to lists for JSON
    area_map = {k: list(v) for k, v in area_map.items()}

    # Build router-id → device name map for frontend neighbor resolution
    router_id_map = {}
    for device_name, data in results.items():
        rid = data.get("router_id")
        if rid:
            router_id_map[rid] = device_name

    return jsonify({
        "devices": results,
        "areas": area_map,
        "link_costs": link_costs,
        "router_id_map": router_id_map,
        "status": "success"
    })
