#!/usr/bin/env python3
"""
Generate Ansible inventory from shared config/devices.py DEVICES dict.
Run this script to create/update ansible/inventory/hosts.yml
"""

import sys
import os
import yaml

# Add project root to path for shared config imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Shared device configuration (single source of truth)
from config.devices import DEVICES, CONTAINERLAB_VM

# Map device_type to Ansible connection settings
DEVICE_TYPE_MAP = {
    "cisco_xe": {
        "ansible_network_os": "cisco.ios.ios",
        "ansible_connection": "ansible.netcommon.network_cli",
    },
    "linux": {
        "ansible_connection": "ssh",
    },
    "containerlab_srlinux": {
        "ansible_connection": "local",
        "containerlab_type": "srlinux",
    },
    "containerlab_frr": {
        "ansible_connection": "local",
        "containerlab_type": "frr",
    },
    "containerlab_linux": {
        "ansible_connection": "local",
        "containerlab_type": "linux",
    },
}


def generate_inventory():
    """Generate Ansible inventory YAML from DEVICES dict."""

    inventory = {
        "all": {
            "children": {
                "cisco_routers": {"hosts": {}},
                "cisco_switches": {"hosts": {}},
                "linux_hosts": {"hosts": {}},
                "containerlab": {
                    "hosts": {},
                    "vars": {
                        "containerlab_vm": CONTAINERLAB_VM,
                    }
                },
            }
        }
    }

    for device_name, device_info in DEVICES.items():
        device_type = device_info.get("device_type", "")
        host_entry = {
            "ansible_host": device_info.get("host"),
        }

        # Add type-specific settings
        type_settings = DEVICE_TYPE_MAP.get(device_type, {})
        host_entry.update(type_settings)

        # Add container name for containerlab devices
        if device_type.startswith("containerlab_"):
            host_entry["container_name"] = device_info.get("container")

        # Categorize into groups
        if device_type == "cisco_xe":
            if device_name.startswith("Switch"):
                inventory["all"]["children"]["cisco_switches"]["hosts"][device_name] = host_entry
            else:
                inventory["all"]["children"]["cisco_routers"]["hosts"][device_name] = host_entry
        elif device_type == "linux":
            inventory["all"]["children"]["linux_hosts"]["hosts"][device_name] = host_entry
        elif device_type.startswith("containerlab_"):
            inventory["all"]["children"]["containerlab"]["hosts"][device_name] = host_entry

    return inventory


def main():
    inventory = generate_inventory()

    # Write to inventory file
    output_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "inventory",
        "hosts.yml"
    )

    with open(output_path, "w") as f:
        yaml.dump(inventory, f, default_flow_style=False, sort_keys=False)

    print(f"Inventory written to: {output_path}")
    print(f"Total devices: {len(DEVICES)}")
    print(f"  - Cisco routers: {sum(1 for d in DEVICES.values() if d['device_type'] == 'cisco_xe' and not d.get('host', '').startswith('Switch'))}")
    print(f"  - Cisco switches: {sum(1 for d, info in DEVICES.items() if info['device_type'] == 'cisco_xe' and d.startswith('Switch'))}")
    print(f"  - Linux hosts: {sum(1 for d in DEVICES.values() if d['device_type'] == 'linux')}")
    print(f"  - Containerlab: {sum(1 for d in DEVICES.values() if d['device_type'].startswith('containerlab_'))}")


if __name__ == "__main__":
    main()
