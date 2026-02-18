"""
NetworkOps Device Inventory Template

Instructions:
1. Copy this file to devices.py: cp devices_template.py devices.py
2. Replace the example devices with your own
3. Ensure SSH/NETCONF access is configured on your devices

Supported device types:
- cisco_xe: Cisco IOS-XE (routers, switches) - SSH + NETCONF
- cisco_ios: Cisco IOS (legacy) - SSH only
- linux: Linux hosts - SSH only
- containerlab_frr: FRRouting in Containerlab
- containerlab_srlinux: Nokia SR Linux in Containerlab
"""

# =============================================================================
# DEFAULT CREDENTIALS
# =============================================================================
# These are used if not specified per-device
# Override in .env or per-device below

USERNAME = "admin"
PASSWORD = "admin"

# =============================================================================
# DEVICE INVENTORY
# =============================================================================
# Each device needs:
#   - host: IP address or hostname (required)
#   - device_type: Platform type (required)
#   - username/password: Uses defaults above if not specified
#   - port: SSH port, defaults to 22
#   - netconf_port: NETCONF port, defaults to 830 (Cisco IOS-XE only)

DEVICES = {
    # -------------------------------------------------------------------------
    # Example: Cisco IOS-XE Router
    # -------------------------------------------------------------------------
    "router1": {
        "host": "192.168.1.10",
        "device_type": "cisco_xe",
        "username": USERNAME,
        "password": PASSWORD,
        "netconf_port": 830,  # Enable with: netconf-yang on device
    },

    # -------------------------------------------------------------------------
    # Example: Cisco IOS-XE Switch
    # -------------------------------------------------------------------------
    "switch1": {
        "host": "192.168.1.20",
        "device_type": "cisco_xe",
        "username": USERNAME,
        "password": PASSWORD,
    },

    # -------------------------------------------------------------------------
    # Example: Linux Server
    # -------------------------------------------------------------------------
    "server1": {
        "host": "192.168.1.100",
        "device_type": "linux",
        "username": "root",
        "password": "password",
    },

    # -------------------------------------------------------------------------
    # Example: Legacy Cisco IOS (no NETCONF)
    # -------------------------------------------------------------------------
    # "legacy-router": {
    #     "host": "192.168.1.30",
    #     "device_type": "cisco_ios",
    #     "username": USERNAME,
    #     "password": PASSWORD,
    # },
}

# =============================================================================
# HELPER FUNCTIONS
# Do not modify these - they are used by the MCP server and dashboard
# =============================================================================

def get_device(name: str) -> dict:
    """Get device configuration by name."""
    if name not in DEVICES:
        raise ValueError(f"Unknown device: {name}. Available: {list(DEVICES.keys())}")
    return DEVICES[name]


def get_all_devices() -> dict:
    """Get all device configurations."""
    return DEVICES


def get_scrapli_device(name: str) -> dict:
    """
    Convert device config to Scrapli format.

    Scrapli uses auth_username/auth_password instead of username/password.
    This function handles the conversion automatically.
    """
    device = get_device(name)

    # Map device_type to Scrapli platform
    platform_map = {
        "cisco_xe": "cisco_iosxe",
        "cisco_ios": "cisco_iosxe",
        "linux": "linux",
    }

    platform = platform_map.get(device["device_type"], device["device_type"])

    return {
        "host": device["host"],
        "auth_username": device.get("username", USERNAME),
        "auth_password": device.get("password", PASSWORD),
        "auth_strict_key": False,
        "transport": "asyncssh",
        "platform": platform,
        "port": device.get("port", 22),
    }


def get_netconf_connection(name: str) -> dict:
    """
    Get NETCONF connection parameters for ncclient.

    Only works for cisco_xe devices with NETCONF enabled.
    """
    device = get_device(name)

    if device["device_type"] not in ["cisco_xe"]:
        raise ValueError(f"NETCONF not supported for {device['device_type']}")

    return {
        "host": device["host"],
        "port": device.get("netconf_port", 830),
        "username": device.get("username", USERNAME),
        "password": device.get("password", PASSWORD),
        "hostkey_verify": False,
        "device_params": {"name": "iosxe"},
    }
