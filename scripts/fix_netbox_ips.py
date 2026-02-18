#!/usr/bin/env python3
"""Fix NetBox IP discrepancies detected by audit."""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
import pynetbox

load_dotenv()

from config.vault_client import get_netbox_token

nb = pynetbox.api(
    os.getenv("NETBOX_URL", "http://localhost:8000"),
    token=get_netbox_token()
)
nb.http_session.verify = False

print("=" * 60)
print("FIXING NETBOX IP DISCREPANCIES")
print("=" * 60)

# 1. Fix IP mismatches on switch uplinks
print("\n[1/3] Fixing IP mismatches on switch uplinks...")

switch_fixes = [
    ("Switch-R1", "GigabitEthernet1/0/1", "10.1.0.11/24", "10.1.0.2/24"),
    ("Switch-R2", "GigabitEthernet1/0/1", "10.2.0.22/24", "10.2.0.2/24"),
    ("Switch-R4", "GigabitEthernet1/0/1", "10.4.0.44/24", "10.4.0.2/24"),
]

for device_name, intf_name, old_ip, new_ip in switch_fixes:
    ip = nb.ipam.ip_addresses.get(address=old_ip)
    if ip:
        ip.address = new_ip
        ip.save()
        print(f"  ✓ {device_name} {intf_name}: {old_ip} → {new_ip}")
    else:
        print(f"  ✗ {device_name} {intf_name}: IP {old_ip} not found")

# 2. Remove stale 203.0.113.x IPs
print("\n[2/3] Removing stale 203.0.113.x IPs...")

stale_ips = [
    "203.0.113.202/22",  # R1 Gi4
    "203.0.113.203/22",  # R2 Gi4
    "203.0.113.204/22",  # R3 Gi4
    "203.0.113.205/22",  # R4 Gi4
    "203.0.113.69/22",   # Switch-R1 Gi0/0
    "203.0.113.80/22",   # Switch-R2 Gi0/0
    "203.0.113.60/22",   # Switch-R4 Gi0/0
    "203.0.113.210/22",  # Alpine-1 eth1
    "203.0.113.211/22",  # Docker-1 eth1
]

for ip_addr in stale_ips:
    ip = nb.ipam.ip_addresses.get(address=ip_addr)
    if ip:
        device_info = ""
        if ip.assigned_object:
            device_info = f" ({ip.assigned_object.device.name} {ip.assigned_object.name})"
        ip.delete()
        print(f"  ✓ Deleted {ip_addr}{device_info}")
    else:
        print(f"  - {ip_addr} not found (already removed?)")

# 3. Add missing IPs
print("\n[3/3] Adding missing IPs...")

missing_ips = [
    ("R1", "Loopback100", "10.100.1.1/32"),
    ("R2", "Loopback100", "10.100.2.2/32"),
    ("R3", "Loopback100", "10.100.3.3/32"),
    ("R4", "Loopback100", "10.100.4.4/32"),
    ("R3", "Tunnel99", "10.99.99.1/30"),
]

for device_name, intf_name, ip_addr in missing_ips:
    # Check if IP already exists
    existing = nb.ipam.ip_addresses.get(address=ip_addr)
    if existing:
        print(f"  - {ip_addr} already exists")
        continue

    # Get device
    device = nb.dcim.devices.get(name=device_name)
    if not device:
        print(f"  ✗ Device {device_name} not found")
        continue

    # Check if interface exists, create if not
    intf = nb.dcim.interfaces.get(device_id=device.id, name=intf_name)
    if not intf:
        intf_type = "virtual" if intf_name.startswith(("Loopback", "Tunnel")) else "other"
        intf = nb.dcim.interfaces.create(
            device=device.id,
            name=intf_name,
            type=intf_type,
            enabled=True
        )
        print(f"  + Created interface {device_name} {intf_name}")

    # Create IP address
    ip = nb.ipam.ip_addresses.create(
        address=ip_addr,
        status="active",
        assigned_object_type="dcim.interface",
        assigned_object_id=intf.id
    )
    print(f"  ✓ Added {ip_addr} to {device_name} {intf_name}")

print("\n" + "=" * 60)
print("COMPLETE")
print("=" * 60)