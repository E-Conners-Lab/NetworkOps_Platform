"""
Shared helpers for operations modules.

These helper functions are used across multiple operations modules
and are extracted here to avoid code duplication.
"""

from config.devices import DEVICES


def is_cisco_device(device_name: str) -> bool:
    """Check if device is a Cisco IOS-XE device."""
    if device_name not in DEVICES:
        return False
    return DEVICES[device_name].get("device_type") == "cisco_xe"


def is_linux_device(device_name: str) -> bool:
    """Check if device is a Linux host."""
    if device_name not in DEVICES:
        return False
    return DEVICES[device_name].get("device_type") == "linux"
