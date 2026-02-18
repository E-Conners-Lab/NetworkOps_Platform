"""
Change Management MCP tools.

This module provides tools for ITIL-compliant change workflows:
- change_create: Create change request
- change_approve: Approve change request
- change_execute: Execute approved change
- change_rollback: Rollback completed/failed change
- change_get: Get change details
- change_list: List change requests
- change_capture_state: Capture device state
"""

import json

from core import log_event


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def change_create(
    device: str,
    description: str,
    commands: str,
    validation_checks: str = "",
    change_type: str = "config",
    require_approval: bool = True,
    auto_rollback: bool = True,
) -> str:
    """
    Create a new change request with pre/post validation.

    The change workflow:
    1. Create → DRAFT
    2. Approve (if required) → APPROVED
    3. Execute → captures pre-state, runs commands, validates
    4. Auto-rollback on failure (if enabled)

    Args:
        device: Target device (e.g., "R1")
        description: Change description
        commands: Config commands (newline or semicolon separated)
        validation_checks: Post-change validation commands (newline or semicolon separated)
        change_type: Type: config, interface, routing, acl, maintenance, emergency
        require_approval: Whether approval is needed before execution
        auto_rollback: Automatically rollback if validation fails

    Returns:
        JSON with change request ID and details

    Examples:
        change_create("R1", "Add loopback", "interface Lo99; ip address 99.99.99.99 255.255.255.255")
        change_create("R1", "Add static route", "ip route 10.99.0.0 255.255.0.0 10.0.12.2", "ping 10.99.0.1")
    """
    from core.change_workflows import get_change_manager, ChangeType

    try:
        manager = get_change_manager()

        # Parse commands and validation checks
        cmd_list = [c.strip() for c in commands.replace(";", "\n").split("\n") if c.strip()]
        check_list = [c.strip() for c in validation_checks.replace(";", "\n").split("\n") if c.strip()] if validation_checks else []

        # Parse change type
        try:
            ctype = ChangeType(change_type)
        except ValueError:
            ctype = ChangeType.CONFIG

        change = await manager.create_change(
            device=device,
            description=description,
            commands=cmd_list,
            change_type=ctype,
            validation_checks=check_list,
            require_approval=require_approval,
            auto_rollback=auto_rollback,
        )

        log_event("change_create", device, f"Change {change.id}: {description}", "success", "operator")

        return json.dumps({
            "id": change.id,
            "device": change.device,
            "description": change.description,
            "status": change.status.value,
            "commands": change.commands,
            "validation_checks": change.validation_checks,
            "rollback_commands": change.rollback_commands,
            "require_approval": change.require_approval,
            "auto_rollback": change.auto_rollback,
            "next_step": "Approve with change_approve() then execute with change_execute()" if require_approval else "Execute with change_execute()",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_approve(change_id: str, approved_by: str = "admin") -> str:
    """
    Approve a change request for execution.

    Args:
        change_id: Change ID to approve
        approved_by: User approving the change

    Returns:
        JSON with updated change status
    """
    from core.change_workflows import get_change_manager

    try:
        manager = get_change_manager()
        change = await manager.approve_change(change_id, approved_by)

        log_event("change_approve", change.device, f"Change {change_id} approved by {approved_by}", "success", "admin")

        return json.dumps({
            "id": change.id,
            "status": change.status.value,
            "approved_at": change.approved_at,
            "approved_by": change.approved_by,
            "next_step": "Execute with change_execute()",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_execute(
    change_id: str,
    skip_validation: bool = False,
) -> str:
    """
    Execute an approved change with pre/post validation.

    This will:
    1. Capture device state (config, routes, interfaces)
    2. Execute the config commands
    3. Run validation checks
    4. Auto-rollback if validation fails (if enabled)

    Args:
        change_id: Change ID to execute
        skip_validation: Skip post-change validation

    Returns:
        JSON with execution result, validation, and any rollback status
    """
    from core.change_workflows import get_change_manager

    try:
        manager = get_change_manager()
        change = await manager.execute_change(change_id, skip_validation=skip_validation)

        log_event("change_execute", change.device,
                  f"Change {change_id}: {change.status.value}",
                  "success" if change.status.value == "completed" else "error", "admin")

        result = {
            "id": change.id,
            "device": change.device,
            "status": change.status.value,
            "executed_at": change.executed_at,
            "completed_at": change.completed_at,
            "execution_output": change.execution_output,
            "error": change.error,
        }

        if change.post_validation:
            result["validation"] = {
                "overall_result": change.post_validation.overall_result.value,
                "checks": change.post_validation.checks,
                "config_changes": len(change.post_validation.config_diff),
                "interface_changes": len(change.post_validation.interface_changes),
                "route_changes": len(change.post_validation.route_changes),
            }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_rollback(change_id: str) -> str:
    """
    Manually rollback a completed or failed change.

    Executes the auto-generated rollback commands to undo the change.

    Args:
        change_id: Change ID to rollback

    Returns:
        JSON with rollback status
    """
    from core.change_workflows import get_change_manager

    try:
        manager = get_change_manager()
        change = await manager.rollback_change(change_id)

        log_event("change_rollback", change.device, f"Change {change_id} rolled back", "success", "admin")

        return json.dumps({
            "id": change.id,
            "device": change.device,
            "status": change.status.value,
            "rollback_commands": change.rollback_commands,
            "execution_output": change.execution_output,
            "error": change.error,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_get(change_id: str) -> str:
    """
    Get details of a change request.

    Args:
        change_id: Change ID to retrieve

    Returns:
        JSON with full change details including pre-state and validation
    """
    from core.change_workflows import get_change_manager

    try:
        manager = get_change_manager()
        change = manager.get_change(change_id)

        if not change:
            return json.dumps({"error": f"Change '{change_id}' not found"})

        return json.dumps(change.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_list(
    device: str = "",
    status: str = "",
    limit: int = 20,
) -> str:
    """
    List change requests.

    Args:
        device: Filter by device (empty = all)
        status: Filter by status (draft, approved, completed, failed, rolled_back)
        limit: Maximum results (default: 20)

    Returns:
        JSON with change request list
    """
    from core.change_workflows import get_change_manager, ChangeStatus

    try:
        manager = get_change_manager()

        status_filter = None
        if status:
            try:
                status_filter = ChangeStatus(status)
            except ValueError:
                pass

        changes = manager.list_changes(
            device=device or None,
            status=status_filter,
            limit=limit,
        )

        return json.dumps({
            "count": len(changes),
            "filters": {"device": device or "all", "status": status or "all"},
            "changes": [
                {
                    "id": c.id,
                    "device": c.device,
                    "description": c.description,
                    "status": c.status.value,
                    "created_at": c.created_at,
                    "completed_at": c.completed_at,
                }
                for c in changes
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def change_capture_state(device: str) -> str:
    """
    Capture current device state (useful for manual comparison).

    Captures running config, interface status, routes, and CDP neighbors.

    Args:
        device: Device to capture

    Returns:
        JSON with captured state summary
    """
    from core.change_workflows import StateCapture

    try:
        state = await StateCapture.capture(device)

        return json.dumps({
            "device": state.device,
            "captured_at": state.captured_at,
            "config_lines": len(state.running_config.split("\n")),
            "interfaces": len(state.interfaces),
            "routes": len(state.routes),
            "neighbors": len(state.neighbors),
            "interface_summary": state.interfaces[:10],
            "route_summary": state.routes[:10],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "device": device}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": change_create, "name": "change_create", "category": "changes"},
    {"fn": change_approve, "name": "change_approve", "category": "changes"},
    {"fn": change_execute, "name": "change_execute", "category": "changes"},
    {"fn": change_rollback, "name": "change_rollback", "category": "changes"},
    {"fn": change_get, "name": "change_get", "category": "changes"},
    {"fn": change_list, "name": "change_list", "category": "changes"},
    {"fn": change_capture_state, "name": "change_capture_state", "category": "changes"},
]
