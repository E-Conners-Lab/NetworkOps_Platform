"""
Interface API Routes.

Interface statistics, remediation, DMVPN status, and switch fabric endpoints.
"""

import re
import subprocess
import logging

from flask import Blueprint, jsonify, request, g
from netmiko import ConnectHandler
from core.errors import safe_error_response, NotFoundError, ValidationError
from dashboard.auth import jwt_required, permission_required

logger = logging.getLogger(__name__)

# Interface name validation: must start with a letter, then letters/digits/slashes/dots/hyphens/underscores.
# Blocks shell metacharacters (;, |, &, $, backticks, etc.) to prevent command injection.
_INTERFACE_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9/._-]{0,63}$')


def _validate_interface_name(name: str) -> None:
    """Validate interface name to prevent command injection.

    Raises ValidationError if the name contains suspicious characters.
    """
    if not name or not _INTERFACE_NAME_RE.match(name):
        raise ValidationError(
            f"Invalid interface name: {name!r}. "
            "Must start with a letter and contain only alphanumeric, '/', '.', '_', '-'."
        )


interfaces_bp = Blueprint('interfaces', __name__)


# Loopback addresses (imported from centralized map)
from config.devices import ROUTER_LOOPBACKS, SWITCH_LOOPBACKS

LOOPBACK_TO_ROUTER = {v: k for k, v in ROUTER_LOOPBACKS.items()}

# Switch uplink configuration
SWITCH_UPLINKS = {
    "Switch-R1": {"router": "R1", "interface": "GigabitEthernet1/0/3"},
    "Switch-R2": {"router": "R2", "interface": "GigabitEthernet1/0/1"},
    "Switch-R4": {"router": "R4", "interface": "GigabitEthernet1/0/1"},
}


def _get_devices():
    """Get devices dictionary from config."""
    from config.devices import DEVICES
    return DEVICES


def _get_containerlab_vm():
    """Get containerlab VM name from config."""
    from config.devices import CONTAINERLAB_VM
    return CONTAINERLAB_VM


def _is_containerlab_device(device_name):
    """Check if device is a containerlab device."""
    from dashboard.api_server import is_containerlab_device
    return is_containerlab_device(device_name)


def _run_containerlab_command(device_name, command):
    """Run command on containerlab device."""
    from dashboard.api_server import run_containerlab_command
    return run_containerlab_command(device_name, command)


def _log_event(action, device, detail, status, username):
    """Log an event."""
    from dashboard.api_server import log_event
    log_event(action, device=device, details=detail, status=status, user=username)


def _invalidate_device_cache(device_name, is_config=False):
    """Invalidate device cache."""
    from dashboard.api_server import invalidate_device_cache
    invalidate_device_cache(device_name, is_config)


# =============================================================================
# Interface Statistics
# =============================================================================

@interfaces_bp.route('/api/interface-stats')
@jwt_required
def get_interface_stats():
    """Get interface statistics for a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_INTERFACES, DEMO_DEVICES
        device_name = request.args.get('device')
        if not device_name:
            raise ValidationError("Missing device parameter")
        if device_name not in DEMO_DEVICES:
            raise NotFoundError(f"Device '{device_name}' not found")
        return jsonify({
            "device": device_name,
            "interfaces": DEMO_INTERFACES.get(device_name, []),
            "status": "success",
        })

    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]

    if _is_containerlab_device(device_name):
        try:
            device_type = device.get('device_type')

            if device_type == 'containerlab_frr':
                output = _run_containerlab_command(device_name, "show interface brief")
            elif device_type == 'containerlab_srlinux':
                output = _run_containerlab_command(device_name, "show interface brief")
            else:
                output = _run_containerlab_command(device_name, "ip -br addr")

            interfaces = []

            if device_type == 'containerlab_srlinux':
                # SR Linux uses table format with | delimiters:
                # | ethernet-1/1  | enable  | down  | 25G | ... |
                for line in output.split('\n'):
                    if '|' not in line or line.startswith('+'):
                        continue
                    # Split by | and filter empty parts
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 3 and parts[0] != 'Port':
                        intf_name = parts[0]
                        admin_state = parts[1].lower() if len(parts) > 1 else 'unknown'
                        oper_state = parts[2].lower() if len(parts) > 2 else 'unknown'
                        # Skip loopback-like interfaces
                        if intf_name in ['lo', 'system0']:
                            continue
                        interfaces.append({
                            "name": intf_name,
                            "status": "up" if oper_state == "up" else "down",
                            "admin_status": admin_state,
                            "rx_rate": 0,
                            "tx_rate": 0,
                            "errors": 0
                        })
            else:
                # FRR and generic Linux parsing
                for line in output.split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        intf_name = parts[0]
                        if intf_name in ['lo', 'sit0'] or intf_name.startswith('br-'):
                            continue
                        interfaces.append({
                            "name": intf_name,
                            "status": "up" if "UP" in line or "up" in line.lower() else "down",
                            "rx_rate": 0,
                            "tx_rate": 0,
                            "errors": 0
                        })

            return jsonify({
                "device": device_name,
                "interfaces": interfaces,
                "status": "success"
            })
        except Exception as e:
            return safe_error_response(e, f"get interface stats for {device_name}")

    try:
        connection = ConnectHandler(**device)
        output = connection.send_command("show interfaces")
        connection.disconnect()

        interfaces = []
        current_intf = None

        for line in output.split('\n'):
            intf_match = re.match(r'^(\S+) is (up|down|administratively down)', line)
            if intf_match:
                if current_intf:
                    interfaces.append(current_intf)
                current_intf = {
                    "name": intf_match.group(1),
                    "status": "up" if "up" in intf_match.group(2) else "down",
                    "rx_rate": 0,
                    "tx_rate": 0,
                    "errors": 0
                }
                continue

            if current_intf:
                bw_match = re.search(r'BW (\d+) Kbit', line)
                if bw_match:
                    current_intf["bandwidth"] = int(bw_match.group(1))

                input_rate = re.search(r'(\d+) bits/sec input', line) or re.search(r'input rate (\d+) bits/sec', line)
                if input_rate:
                    current_intf["rx_rate"] = int(input_rate.group(1))

                output_rate = re.search(r'(\d+) bits/sec output', line) or re.search(r'output rate (\d+) bits/sec', line)
                if output_rate:
                    current_intf["tx_rate"] = int(output_rate.group(1))

                error_match = re.search(r'(\d+) input errors', line)
                if error_match:
                    current_intf["errors"] += int(error_match.group(1))
                error_match = re.search(r'(\d+) output errors', line)
                if error_match:
                    current_intf["errors"] += int(error_match.group(1))

        if current_intf:
            interfaces.append(current_intf)

        interfaces = [i for i in interfaces if i["name"].startswith(('Gi', 'Te', 'Fa', 'Et'))]

        return jsonify({
            "device": device_name,
            "interfaces": interfaces,
            "status": "success"
        })
    except Exception as e:
        return safe_error_response(e, f"get interface stats for {device_name}")


@interfaces_bp.route('/api/interface-acls')
@jwt_required
def get_interface_acls():
    """Get ACL information for all interfaces on a device."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        return jsonify({})

    DEVICES = _get_devices()
    device_name = request.args.get('device')

    if not device_name:
        raise ValidationError("Missing device parameter")

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    if _is_containerlab_device(device_name):
        return jsonify({})

    device = DEVICES[device_name]

    try:
        connection = ConnectHandler(**device)
        output = connection.send_command("show ip interface")
        connection.disconnect()

        acls = {}
        current_intf = None

        for line in output.split('\n'):
            intf_match = re.match(r'^(\S+) is (?:up|down|administratively down)', line)
            if intf_match:
                current_intf = intf_match.group(1)
                acls[current_intf] = {"acl_in": None, "acl_out": None}
                continue

            if current_intf:
                in_match = re.match(r'\s+Inbound\s+access list is (.+)', line)
                if in_match:
                    val = in_match.group(1).strip()
                    acls[current_intf]["acl_in"] = None if val == "not set" else val

                out_match = re.match(r'\s+Outgoing access list is (.+)', line)
                if out_match:
                    val = out_match.group(1).strip()
                    acls[current_intf]["acl_out"] = None if val == "not set" else val

        # Only return interfaces that have an ACL set
        result = {k: v for k, v in acls.items() if v["acl_in"] or v["acl_out"]}
        return jsonify(result)

    except Exception as e:
        return safe_error_response(e, f"get interface ACLs for {device_name}")


@interfaces_bp.route('/api/interface/<device_name>/<interface>')
@jwt_required
def get_interface(device_name, interface):
    """Get detailed information about a specific interface."""
    DEVICES = _get_devices()

    _validate_interface_name(interface)

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    device = DEVICES[device_name]

    try:
        connection = ConnectHandler(**device)
        output = connection.send_command(f"show interface {interface}")
        connection.disconnect()

    except Exception as e:
        return safe_error_response(e, f"get interface {interface} on {device_name}")

    status = {
        "device": device_name,
        "interface": interface,
        "admin_status": "unknown",
        "line_protocol": "unknown",
        "ip_address": None
    }

    first_line = output.split('\n')[0].lower()

    if "administratively down" in first_line:
        status["admin_status"] = "admin_down"
        status["line_protocol"] = "down"
    elif "is up" in first_line:
        status["admin_status"] = "up"
        if "line protocol is up" in first_line:
            status["line_protocol"] = "up"
        else:
            status["line_protocol"] = "down"
    elif "is down" in first_line:
        status["admin_status"] = "down"
        status["line_protocol"] = "down"

    ip_match = re.search(r"Internet address is (\d+\.\d+\.\d+\.\d+/\d+)", output)
    if ip_match:
        status["ip_address"] = ip_match.group(1)

    return jsonify(status)


# =============================================================================
# Interface Remediation
# =============================================================================

@interfaces_bp.route('/api/remediate', methods=['POST'])
@jwt_required
@permission_required('remediate_interfaces')
def remediate():
    """Remediate interface issues (shutdown, no shutdown, bounce)."""
    DEVICES = _get_devices()
    data = request.get_json()

    if not data:
        raise ValidationError("No data provided")

    device_name = data.get('device')
    interface = data.get('interface')
    action = data.get('action', 'no_shutdown')
    username = g.current_user  # Get username from JWT token

    if not device_name or not interface:
        raise ValidationError("Missing device or interface")

    _validate_interface_name(interface)

    if device_name not in DEVICES:
        raise NotFoundError(f"Device '{device_name}' not found")

    valid_actions = ["no_shutdown", "shutdown", "bounce", "remove_acl"]
    if action not in valid_actions:
        raise ValidationError(f"Invalid action. Must be one of: {valid_actions}")

    device = DEVICES[device_name]

    if action == "remove_acl":
        acl_name = data.get('acl_name')
        direction = data.get('direction', 'in')

        if not acl_name or not re.match(r'^[A-Za-z][A-Za-z0-9_-]{0,98}$', acl_name):
            raise ValidationError("Invalid ACL name")
        if direction not in ("in", "out"):
            raise ValidationError("Direction must be 'in' or 'out'")

        commands = [
            f"interface {interface}",
            f"no ip access-group {acl_name} {direction}",
            f"no ip access-list extended {acl_name}",
        ]
    elif action == "no_shutdown":
        commands = [f"interface {interface}", "no shutdown"]
    elif action == "shutdown":
        commands = [f"interface {interface}", "shutdown"]
    elif action == "bounce":
        commands = [f"interface {interface}", "shutdown", "no shutdown"]

    try:
        connection = ConnectHandler(**device)
        output = connection.send_config_set(commands)
        connection.disconnect()
    except Exception as e:
        return safe_error_response(e, f"remediate {interface} on {device_name}")

    try:
        connection = ConnectHandler(**device)
        if action == "remove_acl":
            verify = connection.send_command(f"show ip interface {interface}")
            connection.disconnect()
            direction_label = "Inbound" if direction == "in" else "Outgoing"
            verified = f"{direction_label}  access list is not set" in verify
        else:
            verify = connection.send_command(f"show interface {interface}")
            connection.disconnect()

            first_line = verify.split('\n')[0].lower()
            if action in ["no_shutdown", "bounce"]:
                verified = "administratively down" not in first_line
            else:
                verified = "administratively down" in first_line

    except Exception:
        verified = False

    detail = f"{action} on {interface}"
    if action == "remove_acl":
        detail = f"remove_acl {acl_name} {direction} on {interface}"
    _log_event("remediate", device_name, detail, "success" if verified else "unverified", username)

    # Invalidate cache after interface change
    _invalidate_device_cache(device_name, is_config=True)

    return jsonify({
        "success": True,
        "device": device_name,
        "interface": interface,
        "action": action,
        "verified": verified
    })


# =============================================================================
# DMVPN Status
# =============================================================================

@interfaces_bp.route('/api/dmvpn-status')
@jwt_required
def get_dmvpn_status():
    """Get DMVPN tunnel status from hub router."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_DMVPN_DATA
        return jsonify(DEMO_DMVPN_DATA)

    DEVICES = _get_devices()
    hub_device = "R1"

    if hub_device not in DEVICES:
        raise NotFoundError(f"Hub device '{hub_device}' not found")

    device = DEVICES[hub_device]
    try:
        connection = ConnectHandler(**device)
        dmvpn_output = connection.send_command("show dmvpn")
        connection.disconnect()

        peers = []
        tunnel_name = None
        tunnel_ip = None
        hub_type = None

        lines = dmvpn_output.split('\n')
        for line in lines:
            intf_match = re.search(r'Interface:\s*(\S+)', line)
            if intf_match:
                tunnel_name = intf_match.group(1)

            type_match = re.search(r'Type:(\w+)', line)
            if type_match:
                hub_type = type_match.group(1)

            peer_match = re.match(r'\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\w+)\s+(\S+)\s+(\S+)', line)
            if peer_match:
                nbma_addr = peer_match.group(1)
                tunnel_addr = peer_match.group(2)
                state = peer_match.group(3)
                uptime = peer_match.group(4)
                attr = peer_match.group(5)

                router_name = LOOPBACK_TO_ROUTER.get(nbma_addr, f"Unknown-{nbma_addr}")

                peers.append({
                    "name": router_name,
                    "nbma_addr": nbma_addr,
                    "tunnel_addr": tunnel_addr,
                    "state": state,
                    "uptime": uptime,
                    "type": "spoke",
                    "attr": attr
                })

        try:
            connection = ConnectHandler(**device)
            intf_output = connection.send_command(f"show ip interface {tunnel_name} | include Internet address")
            connection.disconnect()
            ip_match = re.search(r'Internet address is (\S+)', intf_output)
            if ip_match:
                tunnel_ip = ip_match.group(1)
        except Exception:
            tunnel_ip = "unknown"

        return jsonify({
            "status": "success",
            "hub": hub_device,
            "tunnel": tunnel_name,
            "tunnel_ip": tunnel_ip,
            "hub_type": hub_type,
            "peer_count": len(peers),
            "peers_up": len([p for p in peers if p["state"] == "UP"]),
            "peers": peers
        })
    except Exception as e:
        return safe_error_response(e, "get DMVPN status")


# =============================================================================
# Switch Fabric Status
# =============================================================================

@interfaces_bp.route('/api/switch-status')
@jwt_required
def get_switch_status():
    """Get status of all switches including EIGRP neighbors and uplinks."""
    from core.demo import DEMO_MODE
    if DEMO_MODE:
        from core.demo.fixtures import DEMO_SWITCH_DATA
        return jsonify(DEMO_SWITCH_DATA)

    DEVICES = _get_devices()
    switches_data = []

    for switch_name, uplink_info in SWITCH_UPLINKS.items():
        if switch_name not in DEVICES:
            continue

        device = DEVICES[switch_name]
        switch_info = {
            "name": switch_name,
            "ip": device["host"],
            "loopback": SWITCH_LOOPBACKS.get(switch_name, "unknown"),
            "upstream_router": uplink_info["router"],
            "uplink_interface": uplink_info["interface"],
            "status": "unknown",
            "eigrp_neighbor": None,
            "uplink_status": "unknown",
        }

        try:
            connection = ConnectHandler(**device)

            eigrp_output = connection.send_command("show ip eigrp neighbors")

            for line in eigrp_output.split('\n'):
                match = re.match(r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+(\S+)', line)
                if match:
                    neighbor_ip = match.group(2)
                    intf = match.group(3)
                    uptime = match.group(4)
                    switch_info["eigrp_neighbor"] = {
                        "interface": intf,
                        "neighbor_ip": neighbor_ip,
                        "uptime": uptime,
                        "state": "UP"
                    }
                    break

            intf_output = connection.send_command("show ip interface brief")
            # Extract port number from configured interface (e.g., "1/0/3" from "GigabitEthernet1/0/3")
            port_match = re.search(r'(\d+/\d+/\d+)', uplink_info['interface'])
            port_pattern = port_match.group(1) if port_match else uplink_info['interface']
            for line in intf_output.split('\n'):
                if uplink_info['interface'] in line or line.startswith(uplink_info['interface'][:10]):
                    parts = line.split()
                    if len(parts) >= 5 and port_pattern in parts[0]:
                        switch_info["uplink_status"] = "up" if "up" in parts[4].lower() else "down"
                        switch_info["uplink_ip"] = parts[1] if parts[1] != "unassigned" else None
                        break

            connection.disconnect()

            if switch_info["eigrp_neighbor"] and switch_info["uplink_status"] == "up":
                switch_info["status"] = "healthy"
            elif switch_info["uplink_status"] == "up":
                switch_info["status"] = "degraded"
            else:
                switch_info["status"] = "critical"

        except Exception as e:
            logger.exception(f"Failed to fetch switch status for {switch_name}")
            switch_info["status"] = "critical"
            switch_info["error"] = "Failed to connect to switch"

        switches_data.append(switch_info)

    total = len(switches_data)
    healthy = len([s for s in switches_data if s["status"] == "healthy"])

    return jsonify({
        "status": "success",
        "switches": switches_data,
        "total": total,
        "healthy": healthy,
    })
