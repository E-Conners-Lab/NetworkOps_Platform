"""
Mock device fixtures for demo mode.

Uses RFC 5737 documentation IPs:
- 192.0.2.0/24 (TEST-NET-1) for management addresses
- 198.51.100.0/24 (TEST-NET-2) for loopback addresses
- 203.0.113.0/24 (TEST-NET-3) reserved for future use
"""

# ---------------------------------------------------------------------------
# Device inventory — same schema as config.devices._STATIC_DEVICES
# ---------------------------------------------------------------------------
DEMO_DEVICES: dict[str, dict] = {
    # Cisco IOS-XE Routers
    "R1": {
        "device_type": "cisco_xe",
        "host": "192.0.2.11",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.1",
        "lan_ip": "10.1.0.1",
        "platform": "C8000V",
    },
    "R2": {
        "device_type": "cisco_xe",
        "host": "192.0.2.12",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.2",
        "lan_ip": "10.2.0.1",
        "platform": "C8000V",
    },
    "R3": {
        "device_type": "cisco_xe",
        "host": "192.0.2.13",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.3",
        "lan_ip": "10.3.0.1",
        "platform": "C8000V",
    },
    "R4": {
        "device_type": "cisco_xe",
        "host": "192.0.2.14",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.4",
        "lan_ip": "10.4.0.1",
        "platform": "C8000V",
    },
    # Cisco IOS-XE Switches
    "Switch-R1": {
        "device_type": "cisco_xe",
        "host": "192.0.2.21",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.11",
        "platform": "Cat9kv",
    },
    "Switch-R2": {
        "device_type": "cisco_xe",
        "host": "192.0.2.22",
        "username": "demo",
        "password": "demo",
        "loopback": "198.51.100.22",
        "platform": "Cat9kv",
    },
    # FRR containerlab device
    "edge1": {
        "device_type": "containerlab_frr",
        "container": "clab-datacenter-edge1",
        "host": "192.0.2.50",
        "username": "demo",
        "password": "demo",
        "loopback": "10.255.0.2",
        "platform": "FRRouting",
    },
}

# ---------------------------------------------------------------------------
# Topology links — same schema as config.devices.CONTAINERLAB_LINKS
# ---------------------------------------------------------------------------
DEMO_TOPOLOGY_LINKS: list[dict[str, str]] = [
    {
        "source": "R1",
        "target": "R2",
        "source_intf": "GigabitEthernet2",
        "target_intf": "GigabitEthernet2",
    },
    {
        "source": "R2",
        "target": "R3",
        "source_intf": "GigabitEthernet3",
        "target_intf": "GigabitEthernet2",
    },
    {
        "source": "R3",
        "target": "R4",
        "source_intf": "GigabitEthernet3",
        "target_intf": "GigabitEthernet2",
    },
    {
        "source": "R1",
        "target": "Switch-R1",
        "source_intf": "GigabitEthernet1",
        "target_intf": "GigabitEthernet1/0/1",
    },
    {
        "source": "R2",
        "target": "Switch-R2",
        "source_intf": "GigabitEthernet1",
        "target_intf": "GigabitEthernet1/0/1",
    },
    {
        "source": "R3",
        "target": "edge1",
        "source_intf": "GigabitEthernet4",
        "target_intf": "eth2",
    },
]

# ---------------------------------------------------------------------------
# BGP peers — device_name -> list of peer dicts
# ---------------------------------------------------------------------------
DEMO_BGP_PEERS: dict[str, list[dict]] = {
    "R1": [
        {
            "neighbor": "198.51.100.2",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 8,
            "uptime": "1d02h",
        },
        {
            "neighbor": "198.51.100.3",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 6,
            "uptime": "1d02h",
        },
    ],
    "R2": [
        {
            "neighbor": "198.51.100.1",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 8,
            "uptime": "1d02h",
        },
        {
            "neighbor": "198.51.100.3",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 6,
            "uptime": "1d02h",
        },
    ],
    "R3": [
        {
            "neighbor": "198.51.100.1",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 8,
            "uptime": "1d02h",
        },
        {
            "neighbor": "198.51.100.2",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 6,
            "uptime": "1d02h",
        },
        {
            "neighbor": "10.255.0.2",
            "remote_as": 65100,
            "state": "Established",
            "prefixes_received": 3,
            "uptime": "23h15m",
        },
    ],
    "R4": [
        {
            "neighbor": "198.51.100.3",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 10,
            "uptime": "1d02h",
        },
    ],
    "edge1": [
        {
            "neighbor": "198.51.100.3",
            "remote_as": 65000,
            "state": "Established",
            "prefixes_received": 12,
            "uptime": "23h15m",
        },
    ],
}

# ---------------------------------------------------------------------------
# OSPF adjacencies — device_name -> list of adjacency dicts
# ---------------------------------------------------------------------------
DEMO_OSPF_ADJACENCIES: dict[str, list[dict]] = {
    "R1": [
        {
            "neighbor_id": "198.51.100.2",
            "state": "FULL",
            "interface": "GigabitEthernet2",
        },
    ],
    "R2": [
        {
            "neighbor_id": "198.51.100.1",
            "state": "FULL",
            "interface": "GigabitEthernet2",
        },
        {
            "neighbor_id": "198.51.100.3",
            "state": "FULL",
            "interface": "GigabitEthernet3",
        },
    ],
    "R3": [
        {
            "neighbor_id": "198.51.100.2",
            "state": "FULL",
            "interface": "GigabitEthernet2",
        },
        {
            "neighbor_id": "198.51.100.4",
            "state": "FULL",
            "interface": "GigabitEthernet3",
        },
    ],
    "R4": [
        {
            "neighbor_id": "198.51.100.3",
            "state": "FULL",
            "interface": "GigabitEthernet3",
        },
    ],
}

# ---------------------------------------------------------------------------
# DMVPN tunnels — hub/spoke topology
# ---------------------------------------------------------------------------
DEMO_DMVPN_DATA: dict = {
    "status": "success",
    "hub": "R1",
    "tunnel": "Tunnel0",
    "tunnel_ip": "172.16.0.1",
    "peer_count": 3,
    "peers_up": 3,
    "peers": [
        {
            "name": "R2",
            "nbma_addr": "192.0.2.12",
            "tunnel_addr": "172.16.0.2",
            "state": "UP",
            "uptime": "1d02h",
            "type": "spoke",
        },
        {
            "name": "R3",
            "nbma_addr": "192.0.2.13",
            "tunnel_addr": "172.16.0.3",
            "state": "UP",
            "uptime": "1d02h",
            "type": "spoke",
        },
        {
            "name": "R4",
            "nbma_addr": "192.0.2.14",
            "tunnel_addr": "172.16.0.4",
            "state": "UP",
            "uptime": "23h41m",
            "type": "spoke",
        },
    ],
}

# ---------------------------------------------------------------------------
# Switch fabric status
# ---------------------------------------------------------------------------
DEMO_SWITCH_DATA: dict = {
    "status": "success",
    "healthy": 2,
    "switches": [
        {
            "name": "Switch-R1",
            "ip": "192.0.2.21",
            "loopback": "198.51.100.11",
            "status": "healthy",
            "uplink_interface": "GigabitEthernet1/0/1",
            "uplink_status": "up",
            "upstream_router": "R1",
            "eigrp_neighbor": None,
            "vlan_count": 4,
            "port_count": 24,
            "active_ports": 18,
        },
        {
            "name": "Switch-R2",
            "ip": "192.0.2.22",
            "loopback": "198.51.100.22",
            "status": "healthy",
            "uplink_interface": "GigabitEthernet1/0/1",
            "uplink_status": "up",
            "upstream_router": "R2",
            "eigrp_neighbor": None,
            "vlan_count": 4,
            "port_count": 24,
            "active_ports": 12,
        },
    ],
}

# ---------------------------------------------------------------------------
# Interface statistics — device_name -> list of interface dicts
# ---------------------------------------------------------------------------
DEMO_INTERFACES: dict[str, list[dict]] = {
    "R1": [
        {"name": "GigabitEthernet1", "status": "up", "bandwidth": 1000000, "rx_rate": 12400, "tx_rate": 8200, "errors": 0},
        {"name": "GigabitEthernet2", "status": "up", "bandwidth": 1000000, "rx_rate": 45600, "tx_rate": 38900, "errors": 0},
        {"name": "GigabitEthernet3", "status": "up", "bandwidth": 1000000, "rx_rate": 3200, "tx_rate": 2800, "errors": 0},
    ],
    "R2": [
        {"name": "GigabitEthernet1", "status": "up", "bandwidth": 1000000, "rx_rate": 9800, "tx_rate": 7600, "errors": 0},
        {"name": "GigabitEthernet2", "status": "up", "bandwidth": 1000000, "rx_rate": 38900, "tx_rate": 45600, "errors": 0},
        {"name": "GigabitEthernet3", "status": "up", "bandwidth": 1000000, "rx_rate": 22100, "tx_rate": 19400, "errors": 0},
    ],
    "R3": [
        {"name": "GigabitEthernet2", "status": "up", "bandwidth": 1000000, "rx_rate": 19400, "tx_rate": 22100, "errors": 0},
        {"name": "GigabitEthernet3", "status": "up", "bandwidth": 1000000, "rx_rate": 31200, "tx_rate": 27800, "errors": 0},
        {"name": "GigabitEthernet4", "status": "up", "bandwidth": 1000000, "rx_rate": 5600, "tx_rate": 4100, "errors": 0},
    ],
    "R4": [
        {"name": "GigabitEthernet2", "status": "up", "bandwidth": 1000000, "rx_rate": 27800, "tx_rate": 31200, "errors": 0},
        {"name": "GigabitEthernet3", "status": "up", "bandwidth": 1000000, "rx_rate": 1200, "tx_rate": 900, "errors": 0},
    ],
    "Switch-R1": [
        {"name": "GigabitEthernet1/0/1", "status": "up", "bandwidth": 1000000, "rx_rate": 8200, "tx_rate": 12400, "errors": 0},
        {"name": "GigabitEthernet1/0/2", "status": "up", "bandwidth": 1000000, "rx_rate": 3400, "tx_rate": 2900, "errors": 0},
        {"name": "GigabitEthernet1/0/3", "status": "up", "bandwidth": 1000000, "rx_rate": 1800, "tx_rate": 1200, "errors": 0},
        {"name": "GigabitEthernet1/0/4", "status": "down", "bandwidth": 1000000, "rx_rate": 0, "tx_rate": 0, "errors": 0},
    ],
    "Switch-R2": [
        {"name": "GigabitEthernet1/0/1", "status": "up", "bandwidth": 1000000, "rx_rate": 7600, "tx_rate": 9800, "errors": 0},
        {"name": "GigabitEthernet1/0/2", "status": "up", "bandwidth": 1000000, "rx_rate": 2100, "tx_rate": 1700, "errors": 0},
        {"name": "GigabitEthernet1/0/3", "status": "down", "bandwidth": 1000000, "rx_rate": 0, "tx_rate": 0, "errors": 0},
    ],
    "edge1": [
        {"name": "eth1", "status": "up", "bandwidth": 1000000, "rx_rate": 4100, "tx_rate": 5600, "errors": 0},
        {"name": "eth2", "status": "up", "bandwidth": 1000000, "rx_rate": 2200, "tx_rate": 1800, "errors": 0},
    ],
}
