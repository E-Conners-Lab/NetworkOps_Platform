"""
Operations MCP tools facade.

This module provides operational tools for network management.
Functions are organized into domain-specific submodules:

- interfaces.py: get_interface_status, remediate_interface, get_qos_stats
- health.py: linux_health_check, get_cpu_memory
- diagnostics.py: get_arp_table, get_mac_table, ping_sweep, traceroute
- routing.py: get_routing_table, get_neighbors
- sessions.py: get_active_sessions, get_aaa_config, acl_analysis, get_logs
- bulk.py: bulk_command, cache_status

Import Rules:
- External callers: Use `from mcp_tools.operations import X` (this facade)
- Internal modules: Use `from mcp_tools.submodule import X` (direct imports)
"""

# =============================================================================
# Import TOOLS from submodules
# =============================================================================
from .interfaces import TOOLS as _interfaces_tools
from .health import TOOLS as _health_tools
from .diagnostics import TOOLS as _diagnostics_tools
from .routing import TOOLS as _routing_tools
from .sessions import TOOLS as _sessions_tools
from .bulk import TOOLS as _bulk_tools

# =============================================================================
# Combined TOOLS registry
# =============================================================================
TOOLS = (
    _interfaces_tools +
    _health_tools +
    _diagnostics_tools +
    _routing_tools +
    _sessions_tools +
    _bulk_tools
)

# =============================================================================
# Re-export functions for backward compatibility
# =============================================================================

# Interface operations
from .interfaces import (
    get_interface_status,
    remediate_interface,
    get_qos_stats,
)

# Health operations
from .health import (
    linux_health_check,
    get_cpu_memory,
)

# Diagnostics operations
from .diagnostics import (
    get_arp_table,
    get_mac_table,
    ping_sweep,
    traceroute,
)

# Routing operations
from .routing import (
    get_routing_table,
    get_neighbors,
)

# Session/Security operations
from .sessions import (
    get_active_sessions,
    get_aaa_config,
    acl_analysis,
    get_logs,
)

# Bulk operations
from .bulk import (
    bulk_command,
    cache_status,
)

# Helper functions
from ._ops_helpers import (
    is_cisco_device,
    is_linux_device,
)

# =============================================================================
# Public API
# =============================================================================
__all__ = [
    # TOOLS registry
    "TOOLS",

    # Interface operations
    "get_interface_status",
    "remediate_interface",
    "get_qos_stats",

    # Health operations
    "linux_health_check",
    "get_cpu_memory",

    # Diagnostics operations
    "get_arp_table",
    "get_mac_table",
    "ping_sweep",
    "traceroute",

    # Routing operations
    "get_routing_table",
    "get_neighbors",

    # Session/Security operations
    "get_active_sessions",
    "get_aaa_config",
    "acl_analysis",
    "get_logs",

    # Bulk operations
    "bulk_command",
    "cache_status",

    # Helpers
    "is_cisco_device",
    "is_linux_device",
]
