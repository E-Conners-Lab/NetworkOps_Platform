"""
Shared device inventory configuration.

This module provides device definitions with optional NetBox integration.
When USE_NETBOX=true, it pulls from NetBox API with fallback to static config.
All other modules should import from here instead of defining their own DEVICES dict.

Credentials are now loaded via SecretsManager (Vault with .env fallback).

Background Refresh:
When USE_NETBOX=true, a background thread refreshes the device list every
NETBOX_REFRESH_INTERVAL seconds (default: 30). This ensures the dashboard
stays in sync with NetBox without requiring manual refreshes.
"""

import os
import sys
import threading
import time
import atexit
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# Credential Management with Lazy Loading and TTL Cache
# =============================================================================

# Credential cache with TTL
_credential_cache = {
    "username": None,
    "password": None,
    "last_refresh": 0,
}
CREDENTIAL_CACHE_TTL = int(os.getenv("CREDENTIAL_CACHE_TTL", "300"))  # 5 minutes default


def _refresh_credentials_if_needed() -> tuple[str, str]:
    """
    Get credentials with lazy loading and TTL-based refresh.

    Credentials are cached for CREDENTIAL_CACHE_TTL seconds to avoid
    repeated Vault/env lookups, but are automatically refreshed after expiry.

    Returns:
        Tuple of (username, password)
    """
    global _credential_cache

    current_time = time.time()
    cache_age = current_time - _credential_cache["last_refresh"]

    # Return cached credentials if still valid
    if (
        _credential_cache["username"] is not None
        and _credential_cache["password"] is not None
        and cache_age < CREDENTIAL_CACHE_TTL
    ):
        return _credential_cache["username"], _credential_cache["password"]

    # Refresh credentials from Vault or .env
    from config.vault_client import get_device_credentials
    username, password = get_device_credentials()

    _credential_cache["username"] = username
    _credential_cache["password"] = password
    _credential_cache["last_refresh"] = current_time

    return username, password


def get_current_credentials() -> tuple[str, str]:
    """
    Get the current device credentials.

    This function ensures credentials are refreshed when the cache expires,
    supporting credential rotation without application restart.

    Returns:
        Tuple of (username, password)
    """
    return _refresh_credentials_if_needed()


def invalidate_credential_cache():
    """
    Force credential cache invalidation.

    Call this after credential rotation to ensure fresh credentials
    are fetched on the next access.
    """
    global _credential_cache
    _credential_cache["username"] = None
    _credential_cache["password"] = None
    _credential_cache["last_refresh"] = 0


# Initial credential load for backward compatibility
# Note: Prefer using get_current_credentials() for fresh credentials
USERNAME, PASSWORD = get_current_credentials()

# Containerlab VM name
CONTAINERLAB_VM = os.getenv("CONTAINERLAB_VM", "containerlab")

# SSH host key verification (disabled by default for lab environment)
SSH_STRICT_KEY = os.getenv("SSH_STRICT_KEY", "false").lower() == "true"

# =============================================================================
# Device Type Constants
# =============================================================================
# Juniper device types
JUNIPER_TYPES = ["juniper_junos"]

# HPE device types (Aruba CX, ProCurve legacy, Comware)
HPE_TYPES = ["aruba_aoscx", "hp_procurve", "hp_comware"]

# All supported device types for reference
SUPPORTED_DEVICE_TYPES = [
    "cisco_xe",       # Cisco IOS-XE (routers, switches)
    "linux",          # Linux hosts
    "juniper_junos",  # Juniper Junos (vMX, SRX, QFX)
    "aruba_aoscx",    # HPE Aruba CX (AOS-CX)
    "hp_procurve",    # HPE ProCurve (legacy)
    "hp_comware",     # HPE Comware (H3C-derived)
    "containerlab_srlinux",  # Nokia SR Linux (containerlab)
    "containerlab_frr",      # FRRouting (containerlab)
    "containerlab_linux",    # Alpine Linux (containerlab)
]

# NetBox integration settings
USE_NETBOX = os.getenv("USE_NETBOX", "false").lower() == "true"
NETBOX_REFRESH_INTERVAL = int(os.getenv("NETBOX_REFRESH_INTERVAL", "15"))  # seconds
_netbox_loaded = False
_refresh_thread = None
_refresh_stop_event = threading.Event()

# Point-to-point link IPs — used by BGP discovery to resolve peer IPs to device names.
# Only needed for BGP peerings that use link IPs (not mgmt/loopback).
LINK_IP_MAP: dict[str, str] = {
    "10.200.2.1": "R9",   # R9 eth2 (R9↔R10 eBGP link)
    "10.200.2.2": "R10",  # R10 eth1 (R9↔R10 eBGP link)
}

# Containerlab inter-device links (source of truth for topology rendering)
CONTAINERLAB_LINKS: list[dict[str, str]] = [
    {"source": "edge1", "target": "spine1", "source_intf": "eth1", "target_intf": "e1-1"},
    {"source": "spine1", "target": "server1", "source_intf": "e1-2", "target_intf": "eth1"},
    {"source": "spine1", "target": "server2", "source_intf": "e1-3", "target_intf": "eth1"},
    {"source": "spine1", "target": "R9", "source_intf": "e1-4", "target_intf": "eth1"},
    {"source": "R9", "target": "R10", "source_intf": "eth2", "target_intf": "eth1"},
    {"source": "edge1", "target": "R3", "source_intf": "eth2", "target_intf": "Gi4"},
]


# =============================================================================
# Derived Maps — built from DEVICES after initialization
# =============================================================================

def _derive_maps(devices: dict) -> tuple[dict, dict, dict, dict]:
    """Derive loopback and host maps from device inventory.

    Args:
        devices: Device inventory dict (keyed by device name).

    Returns:
        Tuple of (loopback_map, router_loopbacks, switch_loopbacks, device_hosts)
    """
    loopback_map = {name: d["loopback"] for name, d in devices.items() if d.get("loopback")}
    router_loopbacks = {
        k: v for k, v in loopback_map.items()
        if k.startswith("R") and k not in ("R9", "R10")
    }
    switch_loopbacks = {k: v for k, v in loopback_map.items() if k.startswith("Switch-")}
    device_hosts = {name: d["host"] for name, d in devices.items() if d.get("host")}
    return loopback_map, router_loopbacks, switch_loopbacks, device_hosts

# Device inventory (Netmiko format - used by sync server)
_STATIC_DEVICES = {
    # Cisco IOS-XE Routers (Isolated lab network: 10.255.255.0/24)
    "R1": {
        "device_type": "cisco_xe",
        "host": os.getenv("R1_HOST", "10.255.255.11"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.1",
        "lan_ip": "10.1.0.1",
        "platform": "C8000V",
    },
    "R2": {
        "device_type": "cisco_xe",
        "host": os.getenv("R2_HOST", "10.255.255.12"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.2",
        "lan_ip": "10.2.0.1",
        "platform": "C8000V",
    },
    "R3": {
        "device_type": "cisco_xe",
        "host": os.getenv("R3_HOST", "10.255.255.13"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.3",
        "lan_ip": "10.3.0.1",
        "platform": "C8000V",
    },
    "R4": {
        "device_type": "cisco_xe",
        "host": os.getenv("R4_HOST", "10.255.255.14"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.4",
        "lan_ip": "10.4.0.1",
        "platform": "C8000V",
    },
    "R6": {
        "device_type": "cisco_xe",
        "host": os.getenv("R6_HOST", "10.255.255.36"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.6",
        "platform": "C8000V",
    },
    "R7": {
        "device_type": "cisco_xe",
        "host": os.getenv("R7_HOST", "10.255.255.34"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.7",
        "platform": "C8000V",
    },
    # Cisco IOS-XE Switches
    "Switch-R1": {
        "device_type": "cisco_xe",
        "host": os.getenv("SWITCH_R1_HOST", "10.255.255.21"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.11",
        "platform": "Cat9kv",
    },
    "Switch-R2": {
        "device_type": "cisco_xe",
        "host": os.getenv("SWITCH_R2_HOST", "10.255.255.22"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.22",
        "platform": "Cat9kv",
    },
    "Switch-R4": {
        "device_type": "cisco_xe",
        "host": os.getenv("SWITCH_R4_HOST", "10.255.255.24"),
        "username": USERNAME,
        "password": PASSWORD,
        "loopback": "198.51.100.44",
        "platform": "Cat9kv",
    },
    # Linux Hosts
    "Alpine-1": {
        "device_type": "linux",
        "host": os.getenv("ALPINE_1_HOST", "10.255.255.110"),
        "username": USERNAME,
        "password": PASSWORD,
        "connected_to": "R3",
        "local_intf": "eth0",
        "remote_intf": "GigabitEthernet3",
        "lan_ip": "10.3.0.10",
    },
    "Docker-1": {
        "device_type": "linux",
        "host": os.getenv("DOCKER_1_HOST", "10.255.255.111"),
        "username": USERNAME,
        "password": PASSWORD,
        "connected_to": "Switch-R1",
        "local_intf": "eth0",
        "remote_intf": "GigabitEthernet1/0/2",
        "lan_ip": "10.1.1.10",
    },
    # Containerlab Devices (via Multipass VM)
    "spine1": {
        "device_type": "containerlab_srlinux",
        "container": "clab-datacenter-spine1",
        "host": "172.20.20.10",
        "loopback": "10.255.0.1",
        "platform": "Nokia SR Linux",
    },
    "edge1": {
        "device_type": "containerlab_frr",
        "container": "clab-datacenter-edge1",
        "host": "172.20.20.5",
        "loopback": "10.255.0.2",
        "platform": "FRRouting",
    },
    "server1": {
        "device_type": "containerlab_linux",
        "container": "clab-datacenter-server1",
        "host": "172.20.20.20",
        "loopback": "10.100.1.10",
        "platform": "Alpine Linux",
    },
    "server2": {
        "device_type": "containerlab_linux",
        "container": "clab-datacenter-server2",
        "host": "172.20.20.21",
        "loopback": "10.100.2.10",
        "platform": "Alpine Linux",
    },
    "R9": {
        "device_type": "containerlab_frr",
        "container": "clab-datacenter-R9",
        "host": "172.20.20.3",
        "loopback": "198.51.100.9",
        "platform": "FRRouting",
    },
    "R10": {
        "device_type": "containerlab_frr",
        "container": "clab-datacenter-R10",
        "host": "172.20.20.4",
        "loopback": "198.51.100.10",
        "platform": "FRRouting",
    },
}


def get_device(name: str) -> dict | None:
    """Get a device by name.

    Args:
        name: Device name (e.g., 'R1', 'Switch-R1')

    Returns:
        Device dict or None if not found
    """
    return DEVICES.get(name)


def get_devices_by_type(device_type: str) -> dict:
    """Get all devices of a specific type.

    Args:
        device_type: Type to filter by (e.g., 'cisco_xe', 'linux')

    Returns:
        Dict of matching devices
    """
    return {
        name: device
        for name, device in DEVICES.items()
        if device.get("device_type") == device_type
    }


def is_cisco_device(name: str) -> bool:
    """Check if device is a Cisco IOS-XE device."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") == "cisco_xe"


def is_linux_device(name: str) -> bool:
    """Check if device is a Linux host."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") == "linux"


def is_containerlab_device(name: str) -> bool:
    """Check if device is a containerlab device."""
    device = DEVICES.get(name)
    if device is None:
        return False
    device_type = device.get("device_type", "")
    return device_type.startswith("containerlab_")


def is_juniper_device(name: str) -> bool:
    """Check if device is a Juniper Junos device."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") in JUNIPER_TYPES


def is_hpe_device(name: str) -> bool:
    """Check if device is an HPE device (Aruba CX, ProCurve, or Comware)."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") in HPE_TYPES


def is_aruba_cx_device(name: str) -> bool:
    """Check if device is an HPE Aruba CX (AOS-CX) device."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") == "aruba_aoscx"


def is_comware_device(name: str) -> bool:
    """Check if device is an HPE Comware device."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") == "hp_comware"


def is_procurve_device(name: str) -> bool:
    """Check if device is an HPE ProCurve (legacy) device."""
    device = DEVICES.get(name)
    return device is not None and device.get("device_type") == "hp_procurve"


def get_supported_device_types_in_inventory() -> set[str]:
    """Return device types present in current inventory.

    Used for auto-detection: only enable features for device types
    that actually exist in the inventory.

    Returns:
        Set of device_type strings
    """
    return {d.get("device_type") for d in DEVICES.values() if d.get("device_type")}


# =============================================================================
# Scrapli/Async Device Helpers
# =============================================================================

def get_scrapli_device(name: str) -> dict | None:
    """Get Scrapli-compatible device config for async operations.

    Uses fresh credentials from the credential cache to support
    credential rotation without restart.

    Args:
        name: Device name

    Returns:
        Scrapli-compatible device dict or None
    """
    device = DEVICES.get(name)
    if device is None:
        return None

    device_type = device.get("device_type", "")

    # Get fresh credentials (automatically refreshed when TTL expires)
    username, password = get_current_credentials()

    # Base parameters common to most SSH-based devices
    base_params = {
        "host": device["host"],
        "auth_username": username,
        "auth_password": password,
        "auth_strict_key": SSH_STRICT_KEY,
        "transport": "asyncssh",
        "timeout_socket": 10,
        "timeout_transport": 10,
        "device_type": device_type,
    }

    if device_type == "cisco_xe":
        return base_params
    elif device_type == "linux":
        return base_params
    elif device_type == "juniper_junos":
        # Juniper Junos - native Scrapli AsyncJunosDriver support
        return base_params
    elif device_type in HPE_TYPES:
        # HPE devices - use Netmiko (no native Scrapli driver)
        # Mark with use_netmiko flag for connection manager routing
        return {
            **base_params,
            "use_netmiko": True,
            "netmiko_device_type": _get_netmiko_device_type(device_type),
        }
    else:
        # Containerlab or other - return as-is with device_type
        return {**device, "device_type": device_type}


def _get_netmiko_device_type(device_type: str) -> str:
    """Map internal device_type to Netmiko device_type string.

    Args:
        device_type: Internal device type

    Returns:
        Netmiko-compatible device type string
    """
    netmiko_map = {
        "cisco_xe": "cisco_xe",
        "linux": "linux",
        "juniper_junos": "juniper_junos",
        "aruba_aoscx": "aruba_osswitch",  # AOS-CX uses aruba_osswitch driver
        "hp_procurve": "hp_procurve",
        "hp_comware": "hp_comware",
    }
    return netmiko_map.get(device_type, device_type)


def get_all_scrapli_devices() -> dict:
    """Get all devices in Scrapli-compatible format.

    Returns:
        Dict of device_name -> scrapli_config
    """
    return {
        name: get_scrapli_device(name)
        for name in DEVICES
        if get_scrapli_device(name) is not None
    }


# =============================================================================
# NetBox Integration
# =============================================================================

def _load_from_netbox() -> tuple[dict, dict] | None:
    """Try to load device data from NetBox.

    Returns:
        Tuple of (DEVICES, DEVICE_HOSTS) if successful, None otherwise
    """
    try:
        from config.netbox_client import NetBoxClient, is_netbox_available

        if not is_netbox_available():
            return None

        client = NetBoxClient()
        devices = client.get_devices()
        device_hosts = client.get_device_hosts()

        if not devices:
            return None

        return devices, device_hosts
    except ImportError:
        # pynetbox not installed
        return None
    except Exception as e:
        print(f"Warning: Failed to load from NetBox: {e}", file=sys.stderr)
        return None


# Initialize DEVICES and derived maps
# Check for demo mode first, then NetBox, then static config
_demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"

if _demo_mode:
    from core.demo.fixtures import DEMO_DEVICES, DEMO_TOPOLOGY_LINKS
    DEVICES = DEMO_DEVICES
    CONTAINERLAB_LINKS = DEMO_TOPOLOGY_LINKS
    print("Loaded demo device inventory (DEMO_MODE=true)", file=sys.stderr)
elif USE_NETBOX:
    _netbox_data = _load_from_netbox()
    if _netbox_data:
        DEVICES, DEVICE_HOSTS = _netbox_data
        _netbox_loaded = True
        print("Loaded device inventory from NetBox", file=sys.stderr)
    else:
        DEVICES = _STATIC_DEVICES
        print("NetBox unavailable, using static device inventory", file=sys.stderr)
else:
    DEVICES = _STATIC_DEVICES

# Derive loopback and host maps from device inventory.
# For NetBox mode, DEVICE_HOSTS was already set above from NetBox client;
# for static mode, derive it from the enriched _STATIC_DEVICES entries.
LOOPBACK_MAP, ROUTER_LOOPBACKS, SWITCH_LOOPBACKS, _derived_hosts = _derive_maps(DEVICES)
if not USE_NETBOX or not _netbox_loaded:
    DEVICE_HOSTS = _derived_hosts


def is_using_netbox() -> bool:
    """Check if currently using NetBox as data source.

    Returns:
        True if NetBox data is loaded
    """
    return _netbox_loaded


def refresh_from_netbox() -> bool:
    """Force refresh device data from NetBox.

    Updates DEVICES, DEVICE_HOSTS, and derived maps in-place so all modules
    that imported these dicts will see the changes (no stale references).

    Returns:
        True if refresh successful
    """
    global _netbox_loaded

    _netbox_data = _load_from_netbox()
    if _netbox_data:
        new_devices, new_hosts = _netbox_data

        # Update in-place to preserve references in other modules
        DEVICES.clear()
        DEVICES.update(new_devices)

        DEVICE_HOSTS.clear()
        DEVICE_HOSTS.update(new_hosts)

        # Re-derive loopback maps from updated inventory
        new_loopback, new_router_lb, new_switch_lb, _ = _derive_maps(DEVICES)
        LOOPBACK_MAP.clear()
        LOOPBACK_MAP.update(new_loopback)
        ROUTER_LOOPBACKS.clear()
        ROUTER_LOOPBACKS.update(new_router_lb)
        SWITCH_LOOPBACKS.clear()
        SWITCH_LOOPBACKS.update(new_switch_lb)

        _netbox_loaded = True
        return True
    return False


# =============================================================================
# Background Refresh Thread
# =============================================================================

def _background_refresh_loop():
    """Background thread that periodically refreshes device data from NetBox."""
    while not _refresh_stop_event.is_set():
        # Wait for the interval (or until stop is signaled)
        if _refresh_stop_event.wait(timeout=NETBOX_REFRESH_INTERVAL):
            break  # Stop event was set

        # Refresh from NetBox
        try:
            # Clear the NetBox client cache first
            from config.netbox_client import get_client
            client = get_client()
            client.refresh_cache()

            # Then reload devices
            if refresh_from_netbox():
                pass  # Silently refresh - no spam logs
        except Exception as e:
            # Log errors but don't crash the thread
            print(f"Background refresh error: {e}", file=sys.stderr)


def start_background_refresh():
    """Start the background refresh thread if not already running."""
    global _refresh_thread

    if not USE_NETBOX:
        return  # No point refreshing if NetBox is disabled

    if _refresh_thread is not None and _refresh_thread.is_alive():
        return  # Already running

    _refresh_stop_event.clear()
    _refresh_thread = threading.Thread(
        target=_background_refresh_loop,
        name="NetBoxRefresh",
        daemon=True,  # Dies when main process exits
    )
    _refresh_thread.start()
    print(f"Started NetBox background refresh (every {NETBOX_REFRESH_INTERVAL}s)", file=sys.stderr)


def stop_background_refresh():
    """Stop the background refresh thread."""
    global _refresh_thread

    if _refresh_thread is None:
        return

    _refresh_stop_event.set()
    _refresh_thread.join(timeout=5)
    _refresh_thread = None


# Register cleanup on exit
atexit.register(stop_background_refresh)

# Auto-start background refresh if NetBox is enabled
if USE_NETBOX and _netbox_loaded:
    start_background_refresh()
