"""
Device Management API Routes.

Device listing, health checks, and NetBox integration endpoints.
"""

import logging
import subprocess
from core.timestamps import now

from flask import Blueprint, jsonify, request
from netmiko import ConnectHandler
from core.errors import safe_error_response, NotFoundError, ValidationError
from dashboard.auth import jwt_required, permission_required
from core.containerlab import validate_container_name

logger = logging.getLogger(__name__)

devices_bp = Blueprint('devices', __name__)


def _get_devices():
    """Get devices dictionary from config."""
    from config.devices import DEVICES
    return DEVICES


def _get_containerlab_vm():
    """Get containerlab VM name from config."""
    from config.devices import CONTAINERLAB_VM
    return CONTAINERLAB_VM


@devices_bp.route('/api/linux-health/<device_name>')
@jwt_required
def get_linux_health(device_name):
    """Get detailed health metrics for Linux hosts"""
    DEVICES = _get_devices()

    if device_name not in DEVICES:
        return jsonify({"status": "error", "message": "Device not found"}), 404

    device = DEVICES[device_name]
    if device.get("device_type") != "linux":
        return jsonify({"status": "error", "message": "Not a Linux host"}), 400

    result = {
        "status": "healthy",
        "uptime": None,
        "memory": {"total": 0, "used": 0, "free": 0, "percent": 0},
        "disk": {"total": "", "used": "", "available": "", "percent": 0},
        "network": {"gateway_reachable": False}
    }

    try:
        connection = ConnectHandler(**device)

        # Get uptime
        uptime = connection.send_command("uptime -p 2>/dev/null || uptime").strip()
        result["uptime"] = uptime

        # Get memory info and parse it
        mem_output = connection.send_command("free -m 2>/dev/null")
        if mem_output:
            lines = mem_output.strip().split('\n')
            for line in lines:
                if line.startswith('Mem:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        result["memory"]["total"] = int(parts[1])
                        result["memory"]["used"] = int(parts[2])
                        result["memory"]["free"] = int(parts[3])
                        if result["memory"]["total"] > 0:
                            result["memory"]["percent"] = round(
                                (result["memory"]["used"] / result["memory"]["total"]) * 100, 1
                            )

        # Get disk usage and parse it
        disk_output = connection.send_command("df -h / 2>/dev/null | tail -1")
        if disk_output:
            parts = disk_output.split()
            if len(parts) >= 5:
                result["disk"]["total"] = parts[1]
                result["disk"]["used"] = parts[2]
                result["disk"]["available"] = parts[3]
                # Parse percentage (remove % sign)
                try:
                    result["disk"]["percent"] = int(parts[4].replace('%', ''))
                except ValueError:
                    pass

        # Check gateway reachability (use device's gateway based on network)
        gateway = "10.3.0.1" if device_name == "Alpine-1" else "10.4.0.1"
        ping_result = connection.send_command(f"ping -c 1 -W 2 {gateway} 2>/dev/null && echo 'REACHABLE' || echo 'UNREACHABLE'")
        result["network"]["gateway_reachable"] = "REACHABLE" in ping_result

        connection.disconnect()

    except Exception as e:
        logger.exception(f"Linux health check failed for {device_name}")
        result["status"] = "critical"
        result["error"] = "Connection failed"

    return jsonify(result)


@devices_bp.route('/api/containerlab-health/<device_name>')
@jwt_required
def get_containerlab_health(device_name):
    """Get health metrics for containerlab devices"""
    DEVICES = _get_devices()
    CONTAINERLAB_VM = _get_containerlab_vm()

    if device_name not in DEVICES:
        return jsonify({"status": "error", "message": "Device not found"}), 404

    device = DEVICES[device_name]
    if not device.get("device_type", "").startswith("containerlab_"):
        return jsonify({"status": "error", "message": "Not a containerlab device"}), 400

    result = {
        "status": "healthy",
        "container_status": "unknown",
        "uptime": None,
        "memory": {"used": "", "limit": "", "percent": ""},
        "platform": device.get("device_type"),
    }

    container = device.get("container")

    valid, reason = validate_container_name(container or "")
    if not valid:
        return jsonify({"status": "error", "message": reason}), 400

    try:
        # Get container status via docker inspect
        inspect_cmd = f"sudo docker inspect -f '{{{{.State.Status}}}}' {container}"
        proc = subprocess.run(
            ["multipass", "exec", CONTAINERLAB_VM, "--", "bash", "-c", inspect_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            result["container_status"] = proc.stdout.strip()

        # Get container uptime via docker inspect StartedAt
        uptime_cmd = f"sudo docker inspect -f '{{{{.State.StartedAt}}}}' {container}"
        proc = subprocess.run(
            ["multipass", "exec", CONTAINERLAB_VM, "--", "bash", "-c", uptime_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            started_at = proc.stdout.strip()
            # Parse ISO timestamp and calculate uptime
            try:
                # Parse: 2024-12-11T10:30:00.123456789Z
                from datetime import datetime
                started = datetime.fromisoformat(started_at.replace('Z', '+00:00').split('.')[0])
                _now = now()
                # Ensure both are tz-aware for subtraction
                if started.tzinfo is None:
                    from datetime import timezone
                    started = started.replace(tzinfo=timezone.utc)
                delta = _now - started
                days = delta.days
                hours, remainder = divmod(delta.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                if days > 0:
                    result["uptime"] = f"{days}d {hours}h {minutes}m"
                else:
                    result["uptime"] = f"{hours}h {minutes}m"
            except Exception:
                result["uptime"] = started_at

        # Get memory usage via docker stats
        stats_cmd = f"sudo docker stats --no-stream --format '{{{{.MemUsage}}}} {{{{.MemPerc}}}}' {container}"
        proc = subprocess.run(
            ["multipass", "exec", CONTAINERLAB_VM, "--", "bash", "-c", stats_cmd],
            capture_output=True,
            text=True,
            timeout=15
        )
        if proc.returncode == 0:
            # Format: "123.4MiB / 1GiB 12.34%"
            parts = proc.stdout.strip().split()
            if len(parts) >= 3:
                result["memory"]["used"] = parts[0]
                result["memory"]["limit"] = parts[2]
                result["memory"]["percent"] = parts[3] if len(parts) > 3 else ""

        if result["container_status"] != "running":
            result["status"] = "critical"

        # Get interfaces via ip -br addr
        intf_cmd = f"sudo docker exec {container} ip -br addr"
        proc = subprocess.run(
            ["multipass", "exec", CONTAINERLAB_VM, "--", "bash", "-c", intf_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            interfaces = []
            for line in proc.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].split('@')[0]  # Remove @ifXX suffix
                    status = parts[1]
                    # Get first IPv4 address if present
                    ip = None
                    for part in parts[2:]:
                        if '.' in part and '/' in part:  # IPv4 with CIDR
                            ip = part.split('/')[0]
                            break
                    # Skip loopback and tunnel interfaces for cleaner display
                    if name in ('lo', 'gre0', 'gretap0', 'erspan0'):
                        continue
                    interfaces.append({
                        "name": name,
                        "ip": ip,
                        "admin_status": "up" if status == "UP" else "down",
                        "line_protocol": status.lower()
                    })
            result["interfaces"] = interfaces

    except subprocess.TimeoutExpired:
        result["status"] = "critical"
        result["error"] = "Timeout connecting to containerlab VM"
    except Exception as e:
        logger.exception(f"Containerlab health check failed for {device_name}")
        result["status"] = "critical"
        result["error"] = "Connection failed"

    return jsonify(result)


@devices_bp.route('/api/devices')
@jwt_required
def get_devices():
    """
    List all managed devices
    ---
    tags:
      - Devices
    summary: Get device list
    description: Returns list of all network devices in the inventory.
    responses:
      200:
        description: List of device names
        schema:
          type: array
          items:
            type: string
          example: ["R1", "R2", "R3", "R4", "Switch-R1", "Alpine-1"]
    """
    DEVICES = _get_devices()
    return jsonify(list(DEVICES.keys()))


@devices_bp.route('/api/devices', methods=['POST'])
@jwt_required
@permission_required('run_config_commands')
def create_device():
    """
    Create a new device in NetBox
    ---
    tags:
      - Devices
    summary: Create device
    description: Creates a new device in NetBox. Requires admin permissions.
    """
    from dashboard.api_server import cache

    # Check if NetBox is available
    try:
        from config.netbox_client import get_client, is_netbox_available
        if not is_netbox_available():
            return jsonify({"error": "NetBox is not available. Enable USE_NETBOX=true and ensure NetBox is running."}), 400
    except ImportError:
        return jsonify({"error": "NetBox client not available"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Validate required fields
    required = ['name', 'device_type_id', 'role_id', 'site_id']
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        client = get_client()

        # Check if device already exists
        existing = client.get_device(data['name'])
        if existing:
            return jsonify({
                "error": f"Device '{data['name']}' already exists",
                "existing_device": {
                    "id": existing.get("id"),
                    "name": existing.get("name"),
                    "site": existing.get("site", {}).get("name") if existing.get("site") else None,
                }
            }), 409  # Conflict

        result = client.create_device(
            name=data['name'],
            device_type_id=data['device_type_id'],
            role_id=data['role_id'],
            site_id=data['site_id'],
            location_id=data.get('location_id'),
            primary_ip=data.get('primary_ip'),
            netmiko_device_type=data.get('netmiko_device_type'),
            container_name=data.get('container_name'),
        )

        # Clear device cache (non-critical - don't fail if cache unavailable)
        try:
            cache.delete_memoized(get_devices)
        except Exception as cache_err:
            logger.warning(f"Failed to invalidate device cache: {cache_err}")

        return jsonify(result), 201
    except Exception as e:
        err_str = str(e)
        # Check for duplicate name error from NetBox
        if "must be unique" in err_str.lower() or "already exists" in err_str.lower():
            return jsonify({"error": f"Device name '{data['name']}' already exists. Choose a unique name."}), 409
        return safe_error_response(e, "create device in NetBox")


@devices_bp.route('/api/netbox/options')
@jwt_required
@permission_required('run_config_commands')
def get_netbox_options():
    """
    Get dropdown options for device creation form
    ---
    tags:
      - Devices
    summary: Get NetBox dropdown options
    description: Returns sites, locations, device types, and roles for the add device form.
    """
    try:
        from config.netbox_client import get_client, is_netbox_available
        if not is_netbox_available():
            return jsonify({"error": "NetBox is not available"}), 400

        client = get_client()

        # Get netmiko device type options
        netmiko_types = [
            {"value": "cisco_xe", "label": "Cisco IOS-XE"},
            {"value": "cisco_ios", "label": "Cisco IOS"},
            {"value": "linux", "label": "Linux"},
            {"value": "containerlab_srlinux", "label": "Nokia SR Linux (Containerlab)"},
            {"value": "containerlab_frr", "label": "FRRouting (Containerlab)"},
            {"value": "containerlab_linux", "label": "Linux (Containerlab)"},
        ]

        return jsonify({
            "sites": client.get_sites_for_dropdown(),
            "locations": client.get_locations_for_dropdown(),
            "device_types": client.get_device_types(),
            "roles": client.get_device_roles(),
            "netmiko_types": netmiko_types,
        })
    except Exception as e:
        return safe_error_response(e, "get NetBox options")
