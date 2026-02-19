# Demo Mode

Run NetworkOps without any network hardware. Demo mode simulates a 7-device network with realistic protocol data, health metrics, and CLI output.

## Enable

```bash
DEMO_MODE=true python dashboard/api_server.py
# Or via quickstart:
./scripts/quickstart.sh --demo
```

## Simulated Network

| Device | Type | Platform | Loopback |
|--------|------|----------|----------|
| R1 | Router | Cisco C8000V | 198.51.100.1 |
| R2 | Router | Cisco C8000V | 198.51.100.2 |
| R3 | Router | Cisco C8000V | 198.51.100.3 |
| R4 | Router | Cisco C8000V | 198.51.100.4 |
| Switch-R1 | Switch | Cisco Cat9kv | 198.51.100.11 |
| Switch-R2 | Switch | Cisco Cat9kv | 198.51.100.22 |
| edge1 | Router | FRRouting | 10.255.0.2 |

### Topology

```
R1 ──(GE2)── R2 ──(GE3)── R3 ──(GE3)── R4
│(GE1)        │(GE1)        │(GE4)
Switch-R1   Switch-R2      edge1
```

### Protocols

- **OSPF**: R1-R2, R2-R3, R3-R4 (all FULL, Area 0)
- **BGP**: iBGP mesh (R1-R4, AS 65000) + eBGP R3<>edge1 (AS 65100)
- **DMVPN**: Hub R1, spokes R2/R3/R4

## What Works in Demo Mode

| Feature | Status | Notes |
|---------|--------|-------|
| Topology visualization | Full | 7 nodes, 6 links |
| BGP overlay | Full | iBGP + eBGP peers with prefix counts |
| OSPF overlay | Full | Adjacencies, area mapping |
| DMVPN status | Full | Hub-spoke tunnel states |
| Switch fabric | Full | Port counts, uplink status |
| Ping sweep | Full | Simulated 100% reachability |
| Interface stats | Full | Per-device interface list |
| Show commands | Full | Realistic IOS-XE output |
| Config commands | Partial | Accepted; interface shutdown toggles state |
| Health checks | Full | CPU, memory, uptime per device |
| Login / RBAC | Full | JWT auth, admin/operator roles |
| MTU Calculator | Full | No device dependency |
| Subnet Calculator | Full | No device dependency |
| Impact Analysis | Full | No device dependency |
| Intent Drift | Full | No device dependency |
| Change Management | Full | No device dependency |
| Event Log | Full | Records all actions |

### Not Available in Demo Mode

- NETCONF/YANG queries (requires SSH)
- pyATS baselines (requires SSH)
- Streaming telemetry (requires gRPC)
- RAG chat (requires Anthropic API key)
- NetBox integration (requires NetBox instance)

## How It Works

### Connection Layer

When `DEMO_MODE=true`, the connection manager returns a `DemoConnection` instead of a real SSH session:

```python
from core.scrapli_manager import get_ios_xe_connection

async with get_ios_xe_connection("R1") as conn:
    # Returns DemoConnection if DEMO_MODE, real SSH otherwise
    response = await conn.send_command("show ip route")
    print(response.result)  # Simulated IOS-XE output
```

### Route Layer

Dashboard routes check `DEMO_MODE` and return fixture data:

```python
from core.demo import DEMO_MODE
if DEMO_MODE:
    from core.demo.fixtures import DEMO_BGP_PEERS
    return jsonify(DEMO_BGP_PEERS[device_name])
```

### Supported Show Commands

The `DemoDeviceManager` generates realistic output for:

| Command | Output |
|---------|--------|
| `show version` | Platform, uptime, memory |
| `show ip interface brief` | Interface list with status |
| `show ip ospf neighbor` | OSPF adjacency table |
| `show ip bgp summary` | BGP peer table |
| `show ip route` | Routing table |
| `show running-config` | Full device config |
| `show ip arp` | ARP table |
| `show interfaces` | Detailed interface stats |
| `show inventory` | Platform/serial info |
| `show processes cpu` | CPU utilization |
| `ping <IP>` | 100% for known IPs, 0% for unknown |

## Files

```
core/demo/
├── __init__.py            # Exports DEMO_MODE flag
├── fixtures.py            # Static data (devices, BGP, OSPF, DMVPN, interfaces)
├── device_simulator.py    # DemoDeviceManager — stateful command handler
└── connection.py          # DemoConnection — duck-type Scrapli driver
```

All state is in-memory. Restarting the server resets to fixture defaults.
