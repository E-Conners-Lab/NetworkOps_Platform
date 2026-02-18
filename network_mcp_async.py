"""
Async MCP Server for Network Automation

This is a thin wrapper that registers tools from the modular mcp_tools package.
The actual tool implementations are in mcp_tools/*.py modules.

For backwards compatibility, commonly-used functions are re-exported here.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP
from mcp_tools import ALL_TOOLS
from security.tool_wrapper import auth_enforced
from security.tool_auth import MCP_AUTH_ENABLED, set_auth_from_token
from core.tool_metrics import track_tool_call


@asynccontextmanager
async def lifespan(app):
    """Initialize memory system on startup, set auth context for stdio."""
    from memory import MemoryStore
    from memory.context_manager import MemoryAwareToolManager
    from mcp_tools.memory import set_memory_components

    try:
        memory = MemoryStore()
        await memory.initialize()
        manager = MemoryAwareToolManager(memory)
        set_memory_components(memory, manager)
    except Exception:
        pass  # Memory is optional

    # Set auth context from MCP_AUTH_TOKEN env var (stdio transport)
    if MCP_AUTH_ENABLED:
        from config.vault_client import get_mcp_auth_token
        token = get_mcp_auth_token()
        if token:
            from security.token_validator import validate_token

            payload = validate_token(token)
            if payload:
                set_auth_from_token(payload)

    # Warm device cache in the background (non-blocking)
    try:
        from core.cache_warmer import warm_cache
        asyncio.create_task(warm_cache())
    except Exception:
        pass  # Cache warming is optional

    yield  # Server runs here


# Create the MCP server instance with lifespan
mcp = FastMCP("network-lab-async", lifespan=lifespan)

# Register all tools, wrapping with metrics tracking and auth enforcement
for _entry in ALL_TOOLS:
    _tracked = track_tool_call(_entry["name"], _entry["fn"])
    _wrapped = auth_enforced(_entry["name"], _tracked)
    mcp.tool()(_wrapped)


# =============================================================================
# Backwards Compatibility Exports
# =============================================================================
# These imports allow existing code to continue using:
#   from network_mcp_async import health_check, send_command, etc.

# Device tools
from mcp_tools.device import (
    get_devices,
    send_command,
    send_config,
    health_check,
    health_check_all,
    _check_juniper_device,  # Used by tests
)

# Config/operations tools
from mcp_tools.config import (
    backup_config,
    list_backups,
    full_network_test,
)

from mcp_tools.operations import (
    bulk_command,
)

# Testing/pyATS tools
from mcp_tools.testing import (
    pyats_interface_report,
)

# SNMP tools
from mcp_tools.snmp import (
    snmp_poll_metrics,
    snmp_poll_all_devices,
)

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    mcp.run()
