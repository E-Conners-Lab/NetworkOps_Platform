"""
Remediation Playbooks MCP tools.

This module provides tools for automated remediation playbooks:
- playbook_list: List available playbooks
- playbook_detail: Get playbook details
- playbook_execute: Execute a playbook
- playbook_history: Get execution history
- playbook_execution_detail: Get execution details
"""

import json


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def playbook_list(category: str = None, tag: str = None) -> str:
    """
    List available remediation playbooks.

    Args:
        category: Filter by category (Interface, Routing, System, VPN, Layer2)
        tag: Filter by tag (e.g., "ospf", "bgp", "interface")

    Returns:
        JSON with available playbooks and their descriptions
    """
    from core.remediation_playbooks import get_playbook_executor

    try:
        executor = get_playbook_executor()
        playbooks = executor.list_playbooks(category, tag)

        # Simplify output for listing
        summary = []
        for pb in playbooks:
            summary.append({
                "id": pb["id"],
                "name": pb["name"],
                "description": pb["description"],
                "category": pb["category"],
                "parameters": pb["parameters"],
                "requires_approval": pb["requires_approval"],
            })

        return json.dumps({
            "count": len(summary),
            "playbooks": summary,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def playbook_detail(playbook_id: str) -> str:
    """
    Get detailed information about a playbook.

    Args:
        playbook_id: ID of the playbook (e.g., "interface_bounce")

    Returns:
        JSON with full playbook details including all steps
    """
    from core.remediation_playbooks import get_playbook_executor

    try:
        executor = get_playbook_executor()
        playbook = executor.get_playbook(playbook_id)

        if not playbook:
            return json.dumps({
                "error": f"Playbook '{playbook_id}' not found"
            }, indent=2)

        return json.dumps(playbook.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def playbook_execute(
    playbook_id: str,
    device: str,
    dry_run: bool = True,
    interface: str = None,
    neighbor_ip: str = None,
    mtu: str = None,
    acl_name: str = None,
) -> str:
    """
    Execute a remediation playbook.

    IMPORTANT: Use dry_run=True (default) to preview changes before applying.
    Set dry_run=False only when ready to make actual changes.

    Args:
        playbook_id: ID of the playbook to execute
        device: Target device name
        dry_run: If True, simulate without making changes (default: True)
        interface: Interface name (for interface-related playbooks)
        neighbor_ip: Neighbor IP address (for routing playbooks)
        mtu: MTU value (for MTU playbooks)
        acl_name: ACL name (for ACL-related playbooks)

    Returns:
        JSON with execution results and step-by-step output
    """
    from core.remediation_playbooks import get_playbook_executor

    try:
        executor = get_playbook_executor()

        # Build parameters
        params = {"device": device}
        if interface:
            params["interface"] = interface
        if neighbor_ip:
            params["neighbor_ip"] = neighbor_ip
        if mtu:
            params["mtu"] = mtu
        if acl_name:
            params["acl_name"] = acl_name

        result = await executor.execute(playbook_id, dry_run=dry_run, **params)

        return json.dumps(result.to_dict(), indent=2)
    except ValueError as e:
        return json.dumps({"error": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def playbook_history(
    device: str = None,
    playbook_id: str = None,
    status: str = None,
    limit: int = 20,
) -> str:
    """
    Get playbook execution history.

    Args:
        device: Filter by device name
        playbook_id: Filter by playbook ID
        status: Filter by status (success, failed, rolled_back)
        limit: Maximum number of results (default: 20)

    Returns:
        JSON with execution history
    """
    from core.remediation_playbooks import get_playbook_executor

    try:
        executor = get_playbook_executor()
        history = executor.get_execution_history(device, playbook_id, status, limit)

        return json.dumps({
            "count": len(history),
            "executions": history,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def playbook_execution_detail(execution_id: str) -> str:
    """
    Get detailed results of a specific playbook execution.

    Args:
        execution_id: Execution ID from history

    Returns:
        JSON with full execution details including all step outputs
    """
    from core.remediation_playbooks import get_playbook_executor

    try:
        executor = get_playbook_executor()
        execution = executor.get_execution(execution_id)

        if not execution:
            return json.dumps({
                "error": f"Execution '{execution_id}' not found"
            }, indent=2)

        return json.dumps(execution, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": playbook_list, "name": "playbook_list", "category": "playbooks"},
    {"fn": playbook_detail, "name": "playbook_detail", "category": "playbooks"},
    {"fn": playbook_execute, "name": "playbook_execute", "category": "playbooks"},
    {"fn": playbook_history, "name": "playbook_history", "category": "playbooks"},
    {"fn": playbook_execution_detail, "name": "playbook_execution_detail", "category": "playbooks"},
]
