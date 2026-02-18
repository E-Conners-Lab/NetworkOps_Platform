"""
NetBox data definitions for the network lab.

This file contains all the data needed to populate NetBox with the lab configuration.
"""

# =============================================================================
# Regions
# =============================================================================
REGIONS = [
    {"name": "US West", "slug": "us-west"},
    {"name": "Containerlab", "slug": "containerlab"},
]

# =============================================================================
# Manufacturers
# =============================================================================
MANUFACTURERS = [
    {"name": "Cisco", "slug": "cisco"},
    {"name": "Nokia", "slug": "nokia"},
    {"name": "FRRouting", "slug": "frrouting"},
    {"name": "Alpine", "slug": "alpine"},
    {"name": "Ubuntu", "slug": "ubuntu"},
]

# =============================================================================
# Device Types
# =============================================================================
DEVICE_TYPES = [
    {
        "manufacturer": "cisco",
        "model": "C8000V",
        "slug": "c8000v",
        "u_height": 1,
        "is_full_depth": False,
    },
    {
        "manufacturer": "cisco",
        "model": "Catalyst 9000V",
        "slug": "cat9kv",
        "u_height": 1,
        "is_full_depth": False,
    },
    {
        "manufacturer": "nokia",
        "model": "SR Linux",
        "slug": "srlinux",
        "u_height": 1,
        "is_full_depth": False,
    },
    {
        "manufacturer": "frrouting",
        "model": "FRRouting Container",
        "slug": "frr",
        "u_height": 0,
        "is_full_depth": False,
    },
    {
        "manufacturer": "alpine",
        "model": "Alpine Linux",
        "slug": "alpine-linux",
        "u_height": 0,
        "is_full_depth": False,
    },
    {
        "manufacturer": "ubuntu",
        "model": "Ubuntu Server",
        "slug": "ubuntu-server",
        "u_height": 0,
        "is_full_depth": False,
    },
]

# =============================================================================
# Device Roles
# =============================================================================
DEVICE_ROLES = [
    {"name": "Router", "slug": "router", "color": "2196f3", "vm_role": False},
    {"name": "Switch", "slug": "switch", "color": "4caf50", "vm_role": False},
    {"name": "Host", "slug": "host", "color": "9c27b0", "vm_role": False},
    {"name": "Edge Router", "slug": "edge-router", "color": "ff9800", "vm_role": False},
    {"name": "Spine", "slug": "spine", "color": "e91e63", "vm_role": False},
    {"name": "Server", "slug": "server", "color": "607d8b", "vm_role": False},
]

# =============================================================================
# Sites
# =============================================================================
SITES = [
    {
        "name": "EVE-NG Lab",
        "slug": "eve-ng-lab",
        "status": "active",
        "region": "us-west",
        "description": "EVE-NG virtual network lab",
    },
    {
        "name": "Containerlab VM",
        "slug": "containerlab-vm",
        "status": "active",
        "region": "containerlab",
        "description": "Containerlab topology on Multipass VM",
    },
]

# =============================================================================
# Locations (Racks/Logical Groups)
# =============================================================================
LOCATIONS = [
    # EVE-NG Lab locations
    {
        "name": "Core Routers",
        "slug": "core-rack",
        "site": "eve-ng-lab",
        "description": "Core router infrastructure",
    },
    {
        "name": "Switches",
        "slug": "switch-rack",
        "site": "eve-ng-lab",
        "description": "Layer 2/3 switch infrastructure",
    },
    {
        "name": "Hosts",
        "slug": "host-rack",
        "site": "eve-ng-lab",
        "description": "Linux hosts and servers",
    },
    # Containerlab locations
    {
        "name": "Containerlab Devices",
        "slug": "clab-rack",
        "site": "containerlab-vm",
        "description": "Containerlab network devices",
    },
]

# =============================================================================
# IP Prefixes
# =============================================================================
PREFIXES = [
    # Management network (isolated lab)
    {"prefix": "10.255.255.0/24", "description": "Management Network (Isolated Lab)", "status": "active"},
    # Loopbacks
    {"prefix": "198.51.100.0/24", "description": "Router/Switch Loopbacks (TEST-NET-2)", "status": "reserved"},
    # Point-to-Point links
    {"prefix": "10.0.12.0/30", "description": "R1-R2 P2P Link", "status": "active"},
    {"prefix": "10.0.13.0/30", "description": "R1-R3 P2P Link", "status": "active"},
    {"prefix": "10.0.24.0/30", "description": "R2-R4 P2P Link", "status": "active"},
    {"prefix": "10.0.34.0/30", "description": "R3-R4 P2P Link", "status": "active"},
    {"prefix": "10.0.26.0/30", "description": "R2-R6 P2P Link", "status": "active"},
    {"prefix": "10.0.47.0/30", "description": "R4-R7 P2P Link", "status": "active"},
    # LAN segments
    {"prefix": "10.1.0.0/24", "description": "R1 LAN (Switch-R1)", "status": "active"},
    {"prefix": "10.2.0.0/24", "description": "R2 LAN (Switch-R2)", "status": "active"},
    {"prefix": "10.3.0.0/24", "description": "R3 LAN (Alpine-1)", "status": "active"},
    {"prefix": "10.4.0.0/24", "description": "R4 LAN (Switch-R4)", "status": "active"},
    # Docker-1 LAN
    {"prefix": "10.1.1.0/24", "description": "Docker-1 LAN segment", "status": "active"},
    # DMVPN
    {"prefix": "172.16.0.0/24", "description": "DMVPN Tunnel Network", "status": "active"},
    # Containerlab networks
    {"prefix": "10.100.1.0/24", "description": "Containerlab Server1 Network", "status": "active"},
    {"prefix": "10.100.2.0/24", "description": "Containerlab Server2 Network", "status": "active"},
    {"prefix": "10.200.0.0/24", "description": "Containerlab Spine Network", "status": "active"},
    {"prefix": "172.20.0.0/24", "description": "Containerlab Management", "status": "active"},
    # Containerlab point-to-point links
    {"prefix": "10.200.1.0/30", "description": "spine1-R9 P2P Link", "status": "active"},
    {"prefix": "10.200.2.0/30", "description": "R9-R10 P2P Link", "status": "active"},
    # Containerlab eBGP peering (via container mgmt network)
    {"prefix": "172.20.20.0/24", "description": "Containerlab Management (eBGP R3-edge1)", "status": "active"},
]

# =============================================================================
# Devices
# =============================================================================
DEVICES = [
    # Cisco Routers (EVE-NG)
    {
        "name": "R1",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True, "description": "Updated by NOC team"},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": False, "description": "LAN-Segment-Updated"},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": True, "description": "Management Interface"},
            {"name": "GigabitEthernet5", "type": "1000base-t", "enabled": False, "description": "UNUSED - DISABLED"},
            {"name": "GigabitEthernet6", "type": "1000base-t", "enabled": True, "description": "Docker-1-Direct"},
            {"name": "GigabitEthernet7", "type": "1000base-t", "enabled": True, "description": "Switch-R1"},
            {"name": "Loopback100", "type": "virtual", "enabled": True},
            {"name": "Loopback300", "type": "virtual", "enabled": True},
            {"name": "Tunnel100", "type": "virtual", "enabled": True, "description": "DMVPN-HUB"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.1/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.0.12.1/30", "interface": "GigabitEthernet1", "status": "active"},
            {"address": "10.0.13.1/30", "interface": "GigabitEthernet2", "status": "active"},
            {"address": "10.255.255.11/24", "interface": "GigabitEthernet4", "status": "active", "primary": True},
            {"address": "10.1.1.1/24", "interface": "GigabitEthernet6", "status": "active"},
            {"address": "10.1.0.1/24", "interface": "GigabitEthernet7", "status": "active"},
            {"address": "10.100.1.1/32", "interface": "Loopback100", "status": "active"},
            {"address": "172.16.0.1/24", "interface": "Tunnel100", "status": "active"},
        ],
    },
    {
        "name": "R2",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "Loopback100", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": True, "description": "LAN Interface"},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet5", "type": "1000base-t", "enabled": True, "description": "To R6 Gi2"},
            {"name": "Tunnel100", "type": "virtual", "enabled": True, "description": "DMVPN-SPOKE"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.2/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.100.2.2/32", "interface": "Loopback100", "status": "active"},
            {"address": "10.0.12.2/30", "interface": "GigabitEthernet1", "status": "active"},
            {"address": "10.0.24.1/30", "interface": "GigabitEthernet2", "status": "active"},
            {"address": "10.2.0.1/24", "interface": "GigabitEthernet3", "status": "active"},
            {"address": "10.255.255.12/24", "interface": "GigabitEthernet4", "status": "active", "primary": True},
            {"address": "10.0.26.1/30", "interface": "GigabitEthernet5", "status": "active"},
            {"address": "172.16.0.2/24", "interface": "Tunnel100", "status": "active"},
        ],
    },
    {
        "name": "R3",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "Loopback100", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": False, "description": "UNUSED - DISABLED"},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": True, "description": "LAN Interface"},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet5", "type": "1000base-t", "enabled": True, "description": "Link to R4 Gi5"},
            {"name": "Tunnel99", "type": "virtual", "enabled": True, "description": "GRE to Containerlab edge1"},
            {"name": "Tunnel100", "type": "virtual", "enabled": True, "description": "DMVPN-SPOKE"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.3/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.100.3.3/32", "interface": "Loopback100", "status": "active"},
            {"address": "10.0.13.2/30", "interface": "GigabitEthernet2", "status": "active"},
            {"address": "10.3.0.1/24", "interface": "GigabitEthernet3", "status": "active"},
            {"address": "10.255.255.13/24", "interface": "GigabitEthernet4", "status": "active", "primary": True},
            {"address": "10.0.34.1/30", "interface": "GigabitEthernet5", "status": "active"},
            {"address": "10.99.99.1/30", "interface": "Tunnel99", "status": "active"},
            {"address": "172.16.0.3/24", "interface": "Tunnel100", "status": "active"},
        ],
    },
    {
        "name": "R4",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "Loopback100", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": True, "description": "Link to R7 Gi2"},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": True, "description": "LAN Interface"},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet5", "type": "1000base-t", "enabled": True, "description": "Link to R3 Gi5"},
            {"name": "Tunnel100", "type": "virtual", "enabled": True, "description": "DMVPN-SPOKE"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.4/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.100.4.4/32", "interface": "Loopback100", "status": "active"},
            {"address": "10.0.47.1/30", "interface": "GigabitEthernet1", "status": "active"},
            {"address": "10.0.24.2/30", "interface": "GigabitEthernet2", "status": "active"},
            {"address": "10.4.0.1/24", "interface": "GigabitEthernet3", "status": "active"},
            {"address": "10.255.255.14/24", "interface": "GigabitEthernet4", "status": "active", "primary": True},
            {"address": "10.0.34.2/30", "interface": "GigabitEthernet5", "status": "active"},
            {"address": "172.16.0.4/24", "interface": "Tunnel100", "status": "active"},
        ],
    },
    {
        "name": "R6",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": False},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True, "description": "To R2 Gi5"},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": False},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": True},
        ],
        "ip_addresses": [
            {"address": "198.51.100.6/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.0.26.2/30", "interface": "GigabitEthernet2", "status": "active"},
            {"address": "10.255.255.36/24", "interface": "GigabitEthernet4", "status": "active", "primary": True},
        ],
    },
    {
        "name": "R7",
        "device_type": "c8000v",
        "role": "router",
        "site": "eve-ng-lab",
        "location": "core-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet1", "type": "1000base-t", "enabled": True},
            {"name": "GigabitEthernet2", "type": "1000base-t", "enabled": True, "description": "Link to R4 Gi1"},
            {"name": "GigabitEthernet3", "type": "1000base-t", "enabled": False},
            {"name": "GigabitEthernet4", "type": "1000base-t", "enabled": False},
        ],
        "ip_addresses": [
            {"address": "198.51.100.7/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.255.255.34/24", "interface": "GigabitEthernet1", "status": "active", "primary": True},
            {"address": "10.0.47.2/30", "interface": "GigabitEthernet2", "status": "active"},
        ],
    },
    # Cisco Switches (EVE-NG)
    {
        "name": "Switch-R1",
        "device_type": "cat9kv",
        "role": "switch",
        "site": "eve-ng-lab",
        "location": "switch-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet0/0", "type": "1000base-t", "enabled": True, "description": "Management OOB"},
            {"name": "GigabitEthernet1/0/3", "type": "1000base-t", "enabled": True, "description": "Uplink to R1 Gi7"},
            {"name": "Vlan1", "type": "virtual", "enabled": True},
        ],
        "ip_addresses": [
            {"address": "198.51.100.11/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.255.255.21/24", "interface": "GigabitEthernet0/0", "status": "active", "primary": True},
            {"address": "10.1.0.2/24", "interface": "Vlan1", "status": "active"},
        ],
    },
    {
        "name": "Switch-R2",
        "device_type": "cat9kv",
        "role": "switch",
        "site": "eve-ng-lab",
        "location": "switch-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet0/0", "type": "1000base-t", "enabled": True, "description": "Management OOB"},
            {"name": "GigabitEthernet1/0/1", "type": "1000base-t", "enabled": True, "description": "Uplink to R2 Gi3"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.22/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.255.255.22/24", "interface": "GigabitEthernet0/0", "status": "active", "primary": True},
            {"address": "10.2.0.22/24", "interface": "GigabitEthernet1/0/1", "status": "active"},
        ],
    },
    {
        "name": "Switch-R4",
        "device_type": "cat9kv",
        "role": "switch",
        "site": "eve-ng-lab",
        "location": "switch-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "cisco_xe",
            "netconf_enabled": True,
        },
        "interfaces": [
            {"name": "Loopback0", "type": "virtual", "enabled": True},
            {"name": "GigabitEthernet0/0", "type": "1000base-t", "enabled": True, "description": "Management OOB"},
            {"name": "GigabitEthernet1/0/1", "type": "1000base-t", "enabled": True, "description": "Uplink to R4 Gi3"},
        ],
        "ip_addresses": [
            {"address": "198.51.100.44/32", "interface": "Loopback0", "status": "active"},
            {"address": "10.255.255.24/24", "interface": "GigabitEthernet0/0", "status": "active", "primary": True},
            {"address": "10.4.0.44/24", "interface": "GigabitEthernet1/0/1", "status": "active"},
        ],
    },
    # Linux Hosts (EVE-NG)
    {
        "name": "Alpine-1",
        "device_type": "alpine-linux",
        "role": "host",
        "site": "eve-ng-lab",
        "location": "host-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "linux",
        },
        "interfaces": [
            {"name": "eth0", "type": "1000base-t", "enabled": True, "description": "Data - to R3 Gi3"},
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "Management"},
        ],
        "ip_addresses": [
            {"address": "10.3.0.10/24", "interface": "eth0", "status": "active"},
            {"address": "10.255.255.110/24", "interface": "eth1", "status": "active", "primary": True},
        ],
    },
    {
        "name": "Docker-1",
        "device_type": "ubuntu-server",
        "role": "host",
        "site": "eve-ng-lab",
        "location": "host-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "linux",
        },
        "interfaces": [
            {"name": "eth0", "type": "1000base-t", "enabled": True, "description": "Data - to R1 Gi6"},
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "Management"},
        ],
        "ip_addresses": [
            {"address": "10.1.1.10/24", "interface": "eth0", "status": "active"},
            {"address": "10.255.255.111/24", "interface": "eth1", "status": "active", "primary": True},
        ],
    },
    # Containerlab Devices
    {
        "name": "spine1",
        "device_type": "srlinux",
        "role": "spine",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_srlinux",
            "container_name": "clab-datacenter-spine1",
        },
        "interfaces": [
            {"name": "ethernet-1/1", "type": "1000base-t", "enabled": True, "description": "To edge1 eth1"},
            {"name": "ethernet-1/2", "type": "1000base-t", "enabled": True, "description": "To server1 eth1"},
            {"name": "ethernet-1/3", "type": "1000base-t", "enabled": True, "description": "To server2 eth1"},
            {"name": "ethernet-1/4", "type": "1000base-t", "enabled": True, "description": "To R9 eth1"},
        ],
        "ip_addresses": [
            {"address": "10.200.0.1/24", "interface": "ethernet-1/1", "status": "active", "primary": True},
        ],
    },
    {
        "name": "edge1",
        "device_type": "frr",
        "role": "edge-router",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_frr",
            "container_name": "clab-datacenter-edge1",
            "bgp_asn": 65100,
            "bgp_peers": [
                {
                    "neighbor": "10.255.255.13",
                    "remote_as": 65000,
                    "ebgp_multihop": 5,
                    "update_source": "172.20.20.4",
                },
            ],
            "bgp_networks": [
                {"prefix": "10.100.1.0/24"},
                {"prefix": "10.100.2.0/24"},
                {"prefix": "10.200.0.0/30"},
                {"prefix": "10.200.1.0/30"},
                {"prefix": "10.255.0.2/32"},
                {"prefix": "198.51.100.9/32"},
            ],
            "ospf_enabled": True,
            "ospf_interfaces": [
                {"name": "eth1", "area": "0", "mtu_ignore": True, "network_type": "point-to-point", "priority": 50},
                {"name": "lo", "area": "0", "passive": True},
            ],
            "ospf_redistribute": [
                {"type": "connected"},
                {"type": "static", "route_map": "STATIC-TO-OSPF"},
                {"type": "bgp"},
            ],
            "static_routes": [
                {"prefix": "10.0.0.0/8", "next_hop": "172.20.20.1"},
                {"prefix": "203.0.113.0/22", "next_hop": "172.20.20.1"},
                {"prefix": "10.100.1.0/24", "next_hop": "10.200.0.1"},
                {"prefix": "10.100.2.0/24", "next_hop": "10.200.0.1"},
                {"prefix": "10.200.1.0/24", "next_hop": "10.200.0.1"},
                {"prefix": "10.255.255.0/24", "next_hop": "172.20.20.1"},
                {"prefix": "198.51.100.0/24", "next_hop": "10.255.255.13"},
                {"prefix": "10.200.1.0/30", "next_hop": "10.200.0.1"},
                {"prefix": "10.10.10.10/32", "next_hop": "10.200.0.1"},
                {"prefix": "198.51.100.9/32", "next_hop": "10.200.0.1"},
            ],
            "frr_extra_config": (
                "ip prefix-list LOOPBACKS seq 10 permit 198.51.100.0/24\n"
                "!\n"
                "route-map STATIC-TO-OSPF permit 10\n"
                " match ip address prefix-list LOOPBACKS\n"
                "exit\n"
                "!"
            ),
        },
        "interfaces": [
            {"name": "eth0", "type": "1000base-t", "enabled": True, "description": "Management / eBGP to R3"},
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "To spine1"},
            {"name": "gre1", "type": "virtual", "enabled": True},
            {"name": "lo", "type": "virtual", "enabled": True},
        ],
        "ip_addresses": [
            {"address": "172.20.20.2/24", "interface": "eth0", "status": "active", "primary": True},
            {"address": "10.200.0.2/30", "interface": "eth1", "status": "active"},
            {"address": "10.99.99.2/30", "interface": "gre1", "status": "active"},
            {"address": "10.255.0.2/32", "interface": "lo", "status": "active"},
        ],
    },
    {
        "name": "server1",
        "device_type": "alpine-linux",
        "role": "server",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_linux",
            "container_name": "clab-datacenter-server1",
        },
        "interfaces": [
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "To spine1"},
        ],
        "ip_addresses": [
            {"address": "10.100.1.10/24", "interface": "eth1", "status": "active", "primary": True},
        ],
    },
    {
        "name": "server2",
        "device_type": "alpine-linux",
        "role": "server",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_linux",
            "container_name": "clab-datacenter-server2",
        },
        "interfaces": [
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "To spine1"},
        ],
        "ip_addresses": [
            {"address": "10.100.2.10/24", "interface": "eth1", "status": "active", "primary": True},
        ],
    },
    {
        "name": "R9",
        "device_type": "frr",
        "role": "router",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_frr",
            "container_name": "clab-datacenter-R9",
            "bgp_asn": 65200,
            "bgp_peers": [
                {"neighbor": "10.200.2.2", "remote_as": 65300},
            ],
            "bgp_networks": [
                {"prefix": "198.51.100.9/32"},
                {"prefix": "10.200.1.0/30"},
                {"prefix": "10.200.2.0/30"},
            ],
            "ospf_enabled": True,
            "ospf_interfaces": [
                {"name": "eth1", "mtu_ignore": True, "network_type": "point-to-point"},
                {"network": "10.200.1.0/30", "area": "0"},
                {"network": "198.51.100.9/32", "area": "0"},
            ],
            "ospf_redistribute": [],
            "static_routes": [
                {"prefix": "10.255.0.0/24", "next_hop": "10.200.1.1"},
                {"prefix": "10.200.0.0/30", "next_hop": "10.200.1.1"},
                {"prefix": "198.51.100.1/32", "next_hop": "10.200.1.1"},
                {"prefix": "198.51.100.2/32", "next_hop": "10.200.1.1"},
                {"prefix": "198.51.100.3/32", "next_hop": "10.200.1.1"},
                {"prefix": "198.51.100.4/32", "next_hop": "10.200.1.1"},
            ],
            "frr_extra_config": "",
        },
        "interfaces": [
            {"name": "eth0", "type": "1000base-t", "enabled": True, "description": "Management"},
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "Link to spine1"},
            {"name": "eth2", "type": "1000base-t", "enabled": True, "description": "Link to R10"},
            {"name": "lo", "type": "virtual", "enabled": True},
        ],
        "ip_addresses": [
            {"address": "172.20.20.3/24", "interface": "eth0", "status": "active", "primary": True},
            {"address": "10.200.1.2/30", "interface": "eth1", "status": "active"},
            {"address": "10.200.2.1/30", "interface": "eth2", "status": "active"},
            {"address": "198.51.100.9/32", "interface": "lo", "status": "active"},
        ],
    },
    {
        "name": "R10",
        "device_type": "frr",
        "role": "router",
        "site": "containerlab-vm",
        "location": "clab-rack",
        "status": "active",
        "custom_fields": {
            "netmiko_device_type": "containerlab_frr",
            "container_name": "clab-datacenter-R10",
            "bgp_asn": 65300,
            "bgp_peers": [
                {"neighbor": "10.200.2.1", "remote_as": 65200},
            ],
            "bgp_networks": [
                {"prefix": "198.51.100.10/32"},
                {"prefix": "10.200.2.0/30"},
            ],
            "ospf_enabled": False,
            "ospf_interfaces": [],
            "ospf_redistribute": [],
            "static_routes": [],
            "frr_extra_config": "",
        },
        "interfaces": [
            {"name": "eth0", "type": "1000base-t", "enabled": True, "description": "Management"},
            {"name": "eth1", "type": "1000base-t", "enabled": True, "description": "Link to R9"},
            {"name": "lo", "type": "virtual", "enabled": True},
        ],
        "ip_addresses": [
            {"address": "172.20.20.4/24", "interface": "eth0", "status": "active", "primary": True},
            {"address": "10.200.2.2/30", "interface": "eth1", "status": "active"},
            {"address": "198.51.100.10/32", "interface": "lo", "status": "active"},
        ],
    },
]

# =============================================================================
# Cables / Connections
# =============================================================================
CABLES = [
    # Core router links
    {"a_device": "R1", "a_interface": "GigabitEthernet1", "b_device": "R2", "b_interface": "GigabitEthernet1", "status": "connected"},
    {"a_device": "R1", "a_interface": "GigabitEthernet2", "b_device": "R3", "b_interface": "GigabitEthernet2", "status": "connected"},
    {"a_device": "R2", "a_interface": "GigabitEthernet2", "b_device": "R4", "b_interface": "GigabitEthernet2", "status": "connected"},
    {"a_device": "R3", "a_interface": "GigabitEthernet5", "b_device": "R4", "b_interface": "GigabitEthernet5", "status": "connected"},
    {"a_device": "R2", "a_interface": "GigabitEthernet5", "b_device": "R6", "b_interface": "GigabitEthernet2", "status": "connected"},
    {"a_device": "R4", "a_interface": "GigabitEthernet1", "b_device": "R7", "b_interface": "GigabitEthernet2", "status": "connected"},
    # Router to switch links
    {"a_device": "R1", "a_interface": "GigabitEthernet7", "b_device": "Switch-R1", "b_interface": "GigabitEthernet1/0/3", "status": "connected"},
    {"a_device": "R2", "a_interface": "GigabitEthernet3", "b_device": "Switch-R2", "b_interface": "GigabitEthernet1/0/1", "status": "connected"},
    {"a_device": "R4", "a_interface": "GigabitEthernet3", "b_device": "Switch-R4", "b_interface": "GigabitEthernet1/0/1", "status": "connected"},
    # Router to host links
    {"a_device": "R1", "a_interface": "GigabitEthernet6", "b_device": "Docker-1", "b_interface": "eth0", "status": "connected"},
    {"a_device": "R3", "a_interface": "GigabitEthernet3", "b_device": "Alpine-1", "b_interface": "eth0", "status": "connected"},
    # Containerlab links
    {"a_device": "spine1", "a_interface": "ethernet-1/1", "b_device": "edge1", "b_interface": "eth1", "status": "connected"},
    {"a_device": "spine1", "a_interface": "ethernet-1/2", "b_device": "server1", "b_interface": "eth1", "status": "connected"},
    {"a_device": "spine1", "a_interface": "ethernet-1/3", "b_device": "server2", "b_interface": "eth1", "status": "connected"},
    {"a_device": "spine1", "a_interface": "ethernet-1/4", "b_device": "R9", "b_interface": "eth1", "status": "connected"},
    {"a_device": "R9", "a_interface": "eth2", "b_device": "R10", "b_interface": "eth1", "status": "connected"},
]
