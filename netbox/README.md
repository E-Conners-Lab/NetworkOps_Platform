# NetBox Integration

NetworkOps uses [NetBox](https://netbox.dev/) as an optional single source of truth for device inventory, IP address management, and topology data.

## Setup

### 1. Start NetBox

```bash
cd netbox
cp .env.example .env
# Edit .env with your passwords
docker compose up -d
```

This starts NetBox v4.1 with PostgreSQL 15 and Redis 7. Access the UI at `http://localhost:8000`.

### 2. Populate with Lab Data

```bash
python scripts/populate_netbox.py
```

This idempotently creates manufacturers, device types, roles, sites, locations, devices, interfaces, IP prefixes, and cables matching the lab topology.

### 3. Enable in NetworkOps

Add to your `.env`:

```env
USE_NETBOX=true
NETBOX_URL=http://localhost:8000
NETBOX_API_TOKEN=<your-token>
```

## How It Works

When `USE_NETBOX=true`, the device inventory loads from NetBox instead of static config:

```
config/devices.py
├── USE_NETBOX=true
│   ├── NetBox reachable → Load devices, IPs, loopbacks from API
│   └── NetBox unreachable → Fall back to static _STATIC_DEVICES
└── USE_NETBOX=false
    └── Use static config directly
```

### Resilience

- **Circuit breaker**: 3 consecutive failures = open circuit, 60s recovery timeout
- **TTL cache**: 300s default, avoids hammering the API
- **Graceful fallback**: Static config used if NetBox is down at startup

## MCP Tools (14 tools)

| Tool | Description |
|------|-------------|
| `netbox_status` | Health check, version, cache info |
| `netbox_get_devices` | List devices with role/site filters |
| `netbox_get_interfaces` | Interfaces and IPs for a device |
| `netbox_get_prefixes` | IP prefix inventory |
| `netbox_get_ip_addresses` | IP list with device/prefix filters |
| `netbox_get_cables` | Cable connections |
| `netbox_get_hierarchy` | Region > Site > Location > Device tree |
| `netbox_suggest_ip` | Preview next available IP (read-only) |
| `netbox_allocate_ip` | Allocate IP from a prefix |
| `netbox_release_ip` | Release an IP address |
| `netbox_generate_configs` | Generate FRR configs from NetBox data |
| `netbox_generate_iosxe_config` | Generate Cisco running-config |
| `netbox_collect_iosxe_config` | SSH to device, push config to NetBox |
| `netbox_refresh_cache` | Clear in-memory cache |

## Device Type Auto-Detection

NetBox custom fields or device type slugs map to Netmiko driver types:

| Slug Pattern | Driver |
|-------------|--------|
| `c8000v`, `cat9k`, `csr1000v` | `cisco_xe` |
| `vmx`, `junos`, `srx`, `qfx` | `juniper_junos` |
| `aruba-cx`, `aos-cx` | `aruba_aoscx` |
| `srlinux` | `containerlab_srlinux` |
| `frr` | `containerlab_frr` |
| `alpine`, `linux`, `ubuntu` | `linux` |

## IP Allocation

The `netbox_allocate_ip` tool finds the next available IP in a prefix:
- Skips `.1` (gateway) and `.255` (broadcast)
- Avoids collisions with existing allocations
- Optionally assigns to a device interface

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/populate_netbox.py` | Seed NetBox with lab topology (idempotent) |
| `scripts/netbox_data.py` | Data definitions for the lab (regions, sites, devices, cables) |
| `scripts/fix_netbox_ips.py` | Correct IP discrepancies after audit |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `USE_NETBOX` | Enable NetBox as device source | `false` |
| `NETBOX_URL` | NetBox API URL | `http://localhost:8000` |
| `NETBOX_API_TOKEN` | API authentication token | - |
| `NETBOX_CACHE_TTL` | Cache validity (seconds) | `300` |
| `NETBOX_TENANT` | Optional tenant filter | - |
| `NETBOX_VERIFY_SSL` | SSL certificate verification | `true` |
