# MCP Tools

178 tools across 24 categories for AI-powered network management via the [Model Context Protocol](https://modelcontextprotocol.io/).

## Quick Start

```bash
# Run the MCP server
python network_mcp_async.py

# Or configure in Claude Code's MCP settings:
{
  "mcpServers": {
    "networkops": {
      "command": "python",
      "args": ["network_mcp_async.py"]
    }
  }
}
```

## Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| **device** | 5 | Device inventory, send commands, health checks |
| **operations** | 17 | Interfaces, diagnostics, routing, sessions, bulk ops |
| **topology** | 5 | LLDP/CDP discovery, neighbor lookup |
| **config** | 6 | Backup, compare, rollback, export |
| **compliance** | 7 | Compliance checks, templates, remediation |
| **changes** | 7 | Change request workflow (create, approve, execute, rollback) |
| **capacity** | 12 | Baseline collection, forecasting, anomaly detection |
| **testing** | 12 | pyATS state management, CVE checks, aetest runner |
| **netconf** | 3 | YANG/NETCONF interface lookup, BGP neighbors |
| **snmp** | 5 | SNMP get/walk/poll, OID reference |
| **events** | 9 | Event logging, correlation, incident management, RCA |
| **notifications** | 15 | Webhooks, syslog, alerts, ticket creation |
| **orchestration** | 9 | Nornir and Ansible integration |
| **memory** | 13 | Persistent context storage, search, recall |
| **feedback** | 4 | User feedback recording and learning |
| **playbooks** | 5 | Playbook listing, execution, history |
| **scheduling** | 8 | Job creation, scheduling, execution |
| **calculators** | 6 | MTU, subnet, netmask calculations |
| **netbox** | 14 | NetBox inventory, IPAM, config generation |
| **impact** | 18 | Impact analysis, intent drift, blast radius |
| **reporting** | 2 | Report generation |
| **routing** | 2 | Route tables, neighbors |

## Architecture

```
network_mcp_async.py          # MCP server entry point (FastMCP)
mcp_tools/
├── __init__.py                # Registry: ALL_TOOLS, get_tool_by_name(), list_tools_by_category()
├── device.py                  # Core device interaction
├── operations.py              # Facade aggregating submodules:
│   ├── interfaces.py          #   Interface status, remediation, QoS
│   ├── health.py              #   Linux health, CPU/memory
│   ├── diagnostics.py         #   ARP, MAC, ping sweep, traceroute
│   ├── routing.py             #   Route tables, neighbors
│   ├── sessions.py            #   AAA, ACL, logs
│   └── bulk.py                #   Bulk command execution
├── topology.py                # LLDP/CDP discovery
├── config.py                  # Backup, rollback, export
├── compliance.py              # Compliance checks
├── capacity.py                # Forecasting, baselines
├── testing.py                 # pyATS, aetest
├── netconf.py                 # YANG/NETCONF
├── snmp.py                    # SNMP operations
├── events.py                  # Event correlation, RCA
├── notifications.py           # Webhooks, syslog, alerts
├── orchestration.py           # Nornir, Ansible
├── memory.py                  # Context storage
├── feedback.py                # User feedback
├── playbooks.py               # Playbook execution
├── scheduling.py              # Job scheduling
├── calculators.py             # Network math
├── netbox.py                  # NetBox integration
├── impact.py                  # Impact analysis, intent drift
├── reporting.py               # Report generation
├── _shared.py                 # Shared utilities (semaphore, throttling)
└── _ops_helpers.py            # Device type detection helpers
```

## Adding a New Tool

1. Create or edit a module in `mcp_tools/`
2. Define your async function:

```python
async def my_new_tool(device_name: str, option: str = "default") -> str:
    """One-line description shown to the AI model."""
    # Implementation
    return result
```

3. Register it in the module's `TOOLS` list:

```python
TOOLS = [
    {"fn": my_new_tool, "name": "my_new_tool", "category": "my_category"},
]
```

4. Import the module's `TOOLS` in `mcp_tools/__init__.py`

Duplicate tool names are detected at import time and raise `ValueError`.

## Middleware

Every tool is automatically wrapped with:
- **Authentication** via `auth_enforced()` (configurable with `MCP_AUTH_ENABLED`)
- **Metrics tracking** via `track_tool_call()` for observability

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_AUTH_ENABLED` | Enable token authentication | `false` |
| `MCP_AUTH_TOKEN` | Auth token for MCP connections | - |
| `DEMO_MODE` | Use simulated devices | `false` |
