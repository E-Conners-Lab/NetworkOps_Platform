"""
MCP Tools Registry

This module provides a unified registry for all MCP tools with:
- Duplicate name detection at import time
- Category-based organization
- Helper functions for tool registration

Usage:
    from mcp_tools import ALL_TOOLS, get_tool_functions

    for tool_fn in get_tool_functions():
        mcp.add_tool(tool_fn)
"""
from typing import List, Dict, Any, Callable

# Import tool modules
from .device import TOOLS as device_tools
from .memory import TOOLS as memory_tools
from .calculators import TOOLS as calculators_tools
from .scheduling import TOOLS as scheduling_tools
from .topology import TOOLS as topology_tools
from .reporting import TOOLS as reporting_tools
from .notifications import TOOLS as notifications_tools
from .operations import TOOLS as operations_tools
from .netconf import TOOLS as netconf_tools
from .config import TOOLS as config_tools
from .snmp import TOOLS as snmp_tools
from .testing import TOOLS as testing_tools
from .compliance import TOOLS as compliance_tools
from .changes import TOOLS as changes_tools
from .capacity import TOOLS as capacity_tools
from .events import TOOLS as events_tools
from .playbooks import TOOLS as playbooks_tools
from .orchestration import TOOLS as orchestration_tools
from .feedback import TOOLS as feedback_tools
from .impact import TOOLS as impact_tools
from .netbox import TOOLS as netbox_tools


def _build_registry(*tool_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build the ALL_TOOLS registry with uniqueness checking.

    Each tool entry must have:
        - fn: The tool function
        - name: Unique tool name (e.g., "device.get_devices")
        - category: Tool category (e.g., "device", "topology")

    Raises:
        ValueError: If duplicate tool names are detected
    """
    all_tools = []
    seen_names = set()

    for tool_list in tool_lists:
        for entry in tool_list:
            name = entry["name"]
            if name in seen_names:
                raise ValueError(f"Duplicate tool name detected: {name}")
            seen_names.add(name)
            all_tools.append(entry)

    return all_tools


# Build the registry from all imported tool modules
ALL_TOOLS = _build_registry(
    device_tools,
    memory_tools,
    calculators_tools,
    scheduling_tools,
    topology_tools,
    reporting_tools,
    notifications_tools,
    operations_tools,
    netconf_tools,
    config_tools,
    snmp_tools,
    testing_tools,
    compliance_tools,
    changes_tools,
    capacity_tools,
    events_tools,
    playbooks_tools,
    orchestration_tools,
    feedback_tools,
    impact_tools,
    netbox_tools,
)


def get_tool_functions() -> List[Callable]:
    """
    Return list of tool functions for MCP registration.

    Usage:
        for tool_fn in get_tool_functions():
            mcp.add_tool(tool_fn)
    """
    return [entry["fn"] for entry in ALL_TOOLS]


def list_tools_by_category(category: str) -> List[Dict[str, Any]]:
    """
    Return tools filtered by category.

    Args:
        category: Category name (e.g., "device", "topology", "snmp")

    Returns:
        List of tool entries matching the category
    """
    return [t for t in ALL_TOOLS if t["category"] == category]


def get_tool_by_name(name: str) -> Dict[str, Any] | None:
    """
    Get a specific tool by name.

    Args:
        name: Tool name (e.g., "get_devices", "send_command")

    Returns:
        Tool entry dict or None if not found
    """
    for t in ALL_TOOLS:
        if t["name"] == name:
            return t
    return None


def get_categories() -> List[str]:
    """Return list of all unique categories."""
    return list(set(t["category"] for t in ALL_TOOLS))


# Export for convenience
__all__ = [
    "ALL_TOOLS",
    "get_tool_functions",
    "list_tools_by_category",
    "get_tool_by_name",
    "get_categories",
]
