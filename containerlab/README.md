# Containerlab Topology

A 6-node multi-vendor datacenter topology running on [Containerlab](https://containerlab.dev/), providing FRRouting and Nokia SR Linux devices for multi-vendor testing.

## Topology

```
                EVE-NG Lab (10.255.255.0/24)
                        |
                     edge1 (FRR, AS 65100)
                        |
                     [eth1]
                        |
    spine1 (SR Linux) --+
       |    |    |
     e1-2 e1-3 e1-4
       |    |    |
   server1 server2  R9 (FRR, AS 65200)
                      |
                    [eth2]
                      |
                    R10 (FRR, AS 65300)
```

### Devices

| Device | Kind | Image | Role | Mgmt IP |
|--------|------|-------|------|---------|
| spine1 | Nokia SR Linux | `ghcr.io/nokia/srlinux:24.10.1` | Datacenter spine | 172.20.20.10 |
| edge1 | FRRouting | `frrouting/frr:v8.4.1` | Border router (eBGP to EVE-NG) | 172.20.20.5 |
| R9 | FRRouting | `frrouting/frr:v8.4.1` | Internal router | 172.20.20.3 |
| R10 | FRRouting | `frrouting/frr:v8.4.1` | eBGP peer | 172.20.20.4 |
| server1 | Alpine Linux | `alpine:3.19` | Traffic endpoint | 172.20.20.20 |
| server2 | Alpine Linux | `alpine:3.19` | Traffic endpoint | 172.20.20.21 |

### Routing Protocols

- **OSPF Area 0**: spine1, edge1, R9
- **eBGP**: edge1 (AS 65100) peers with EVE-NG R3; R9 (AS 65200) peers with R10 (AS 65300)
- **edge1** redistributes BGP into OSPF for reachability between labs

## IP Addressing

### Management (172.20.20.0/24)

All management IPs are pinned in `datacenter.clab.yml`.

### Data Plane

| Link | Subnet | Description |
|------|--------|-------------|
| spine1 <> edge1 | 10.200.0.0/30 | Point-to-point |
| spine1 <> server1 | 10.100.1.0/24 | Server network |
| spine1 <> server2 | 10.100.2.0/24 | Server network |
| spine1 <> R9 | 10.200.1.0/30 | Point-to-point |
| R9 <> R10 | 10.200.2.0/30 | eBGP peering |

### Loopbacks

| Device | Loopback |
|--------|----------|
| spine1 | 10.255.0.1/32 |
| edge1 | 10.255.0.2/32 |
| R9 | 198.51.100.9/32 |
| R10 | 198.51.100.10/32 |

## Usage

### Deploy

```bash
# From a host with containerlab installed:
cd containerlab
sudo containerlab deploy -t datacenter.clab.yml
```

### Verify

```bash
# Check containers
sudo containerlab inspect --all

# BGP on edge1
sudo docker exec clab-datacenter-edge1 vtysh -c "show ip bgp summary"

# OSPF on spine1
sudo docker exec clab-datacenter-spine1 sr_cli "show network-instance default protocols ospf neighbor"
```

### Destroy

```bash
sudo containerlab destroy -t datacenter.clab.yml
```

## Configuration Files

```
containerlab/configs/
├── spine1.cfg          # Nokia SR Linux: OSPF, interfaces
├── edge1-frr.conf      # FRR: OSPF + BGP AS 65100, SNAT, static routes
├── edge1-daemons       # Enables zebra, bgpd, ospfd
├── R9-frr.conf         # FRR: OSPF + BGP AS 65200
├── R9-daemons          # Enables zebra, bgpd, ospfd
├── R10-frr.conf        # FRR: BGP AS 65300
└── R10-daemons         # Enables zebra, bgpd
```

## Integration with NetworkOps

The main project interacts with containerlab devices via:

- **`core/containerlab.py`** — Command execution, health checks, provisioning (via `docker exec` through multipass)
- **`config/devices.py`** — Registers containerlab devices with `device_type: containerlab_frr` or `containerlab_srlinux`
- **Dashboard** — Containerlab devices appear in the topology with health monitoring
- **MCP Tools** — `send_command` and health check tools work with containerlab devices
