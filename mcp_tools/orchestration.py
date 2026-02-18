"""
Orchestration MCP tools.

This module provides tools for multi-device orchestration using Nornir and Ansible:

Nornir tools (4):
- nornir_run_command: Run command on multiple devices in parallel
- nornir_run_config: Apply configuration to multiple devices
- nornir_get_facts: Gather facts from multiple devices
- nornir_inventory: Get Nornir inventory summary

Ansible tools (5):
- ansible_run_playbook: Execute an Ansible playbook
- ansible_list_playbooks: List available playbooks
- ansible_inventory: Get Ansible inventory
- ansible_summary: Get Ansible configuration summary
- ansible_adhoc: Run ad-hoc Ansible command
"""

import json


# =============================================================================
# Nornir MCP Tool Functions
# =============================================================================

async def nornir_run_command(
    command: str,
    devices: str = None,
    filter_type: str = None,
    filter_pattern: str = None,
) -> str:
    """
    Run a command on multiple devices in parallel using Nornir.

    Much faster than sequential execution for multi-device operations.
    Feature flag: use_nornir (set FF_USE_NORNIR=true to enable)

    Args:
        command: Command to execute (e.g., "show ip interface brief")
        devices: Comma-separated device names (e.g., "R1,R2,R3") - optional
        filter_type: Filter by device_type (e.g., "cisco_xe") - optional
        filter_pattern: Regex pattern to match device names (e.g., "R[1-4]") - optional

    Returns:
        JSON with per-device results and summary statistics

    Examples:
        nornir_run_command("show version")  # All devices
        nornir_run_command("show ip ospf neighbor", filter_type="cisco_xe")
        nornir_run_command("show clock", devices="R1,R2,R3,R4")
        nornir_run_command("show interfaces", filter_pattern="Switch.*")
    """
    from core.nornir_manager import get_nornir
    from core.feature_flags import is_enabled

    if not is_enabled("use_nornir"):
        return json.dumps({
            "error": "Nornir is disabled",
            "hint": "Set FF_USE_NORNIR=true or add use_nornir: true to config/feature_flags.yaml",
        }, indent=2)

    try:
        nr = get_nornir()

        device_list = None
        if devices:
            device_list = [d.strip() for d in devices.split(",")]

        result = nr.run_command(
            command=command,
            devices=device_list,
            filter_type=filter_type,
            filter_pattern=filter_pattern,
        )

        return json.dumps(result.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def nornir_run_config(
    commands: str,
    devices: str = None,
    filter_type: str = None,
    dry_run: bool = True,
) -> str:
    """
    Apply configuration to multiple devices in parallel using Nornir.

    IMPORTANT: Uses dry_run=True by default for safety. Set dry_run=False to apply.

    Args:
        commands: Config commands (semicolon-separated, e.g., "ntp server 198.51.100.1;logging host 198.51.100.2")
        devices: Comma-separated device names (optional)
        filter_type: Filter by device_type (optional)
        dry_run: If True (default), only show what would be configured

    Returns:
        JSON with per-device results

    Examples:
        # Preview config change
        nornir_run_config("logging host 10.0.0.1", filter_type="cisco_xe")

        # Apply to specific devices
        nornir_run_config("banner motd # Warning #", devices="R1,R2", dry_run=False)
    """
    from core.nornir_manager import get_nornir
    from core.feature_flags import is_enabled

    if not is_enabled("use_nornir"):
        return json.dumps({
            "error": "Nornir is disabled",
            "hint": "Set FF_USE_NORNIR=true to enable",
        }, indent=2)

    try:
        nr = get_nornir()

        device_list = None
        if devices:
            device_list = [d.strip() for d in devices.split(",")]

        result = nr.run_config(
            config_commands=commands,
            devices=device_list,
            filter_type=filter_type,
            dry_run=dry_run,
        )

        return json.dumps(result.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def nornir_get_facts(
    devices: str = None,
    filter_type: str = None,
) -> str:
    """
    Gather facts (version, hostname, model, serial) from multiple devices in parallel.

    Args:
        devices: Comma-separated device names (optional)
        filter_type: Filter by device_type (optional)

    Returns:
        JSON with device facts (hostname, version, model, serial, uptime)

    Examples:
        nornir_get_facts()  # All devices
        nornir_get_facts(filter_type="cisco_xe")  # Only Cisco devices
        nornir_get_facts(devices="R1,R2,Switch-R1")  # Specific devices
    """
    from core.nornir_manager import get_nornir
    from core.feature_flags import is_enabled

    if not is_enabled("use_nornir"):
        return json.dumps({
            "error": "Nornir is disabled",
            "hint": "Set FF_USE_NORNIR=true to enable",
        }, indent=2)

    try:
        nr = get_nornir()

        device_list = None
        if devices:
            device_list = [d.strip() for d in devices.split(",")]

        result = nr.get_facts(
            devices=device_list,
            filter_type=filter_type,
        )

        return json.dumps(result.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def nornir_inventory() -> str:
    """
    Get Nornir inventory summary.

    Shows available devices grouped by type and Nornir status.

    Returns:
        JSON with inventory statistics and device lists by type
    """
    from core.nornir_manager import get_nornir

    try:
        nr = get_nornir()
        summary = nr.get_inventory_summary()

        return json.dumps(summary, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Ansible MCP Tool Functions
# =============================================================================

async def ansible_run_playbook(
    playbook: str,
    limit: str = None,
    extra_vars: str = None,
    tags: str = None,
    check_mode: bool = False,
) -> str:
    """
    Execute an Ansible playbook.

    Args:
        playbook: Playbook name (e.g., "health_check", "backup_configs") or full path
        limit: Host pattern to limit execution (e.g., "R1,R2" or "cisco_routers")
        extra_vars: JSON string of extra variables (e.g., '{"commands": ["logging host 198.51.100.1"]}')
        tags: Comma-separated list of tags to run
        check_mode: If True, run in dry-run mode (show what would change)

    Returns:
        JSON with playbook execution results including per-host status

    Examples:
        ansible_run_playbook("health_check")  # Run on all hosts
        ansible_run_playbook("backup_configs", limit="R1,R2,R3,R4")
        ansible_run_playbook("deploy_changes", extra_vars='{"commands": ["logging host 198.51.100.1"]}')
        ansible_run_playbook("compliance_check", check_mode=True)  # Dry run

    Available playbooks:
        - health_check: Check device health (interfaces, OSPF, BGP, EIGRP)
        - backup_configs: Backup running configs to files
        - compliance_check: Run pyATS compliance validation
        - deploy_changes: Apply configuration changes with diff
    """
    from core.ansible_manager import get_ansible
    from core.feature_flags import is_enabled

    if not is_enabled("use_ansible"):
        return json.dumps({
            "error": "Ansible is disabled",
            "hint": "Set FF_USE_ANSIBLE=true to enable",
        }, indent=2)

    try:
        ansible = get_ansible()

        # Parse extra_vars JSON if provided
        extra_vars_dict = None
        if extra_vars:
            extra_vars_dict = json.loads(extra_vars)

        # Parse tags
        tags_list = None
        if tags:
            tags_list = [t.strip() for t in tags.split(",")]

        result = ansible.run_playbook(
            playbook=playbook,
            limit=limit,
            extra_vars=extra_vars_dict,
            tags=tags_list,
            check_mode=check_mode,
        )

        return json.dumps(result.to_dict(), indent=2)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON in extra_vars: {e}"}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def ansible_list_playbooks() -> str:
    """
    List available Ansible playbooks.

    Returns:
        JSON with list of playbooks including name, description, and target hosts

    Example:
        ansible_list_playbooks()
    """
    from core.ansible_manager import get_ansible

    try:
        ansible = get_ansible()
        playbooks = ansible.list_playbooks()

        return json.dumps({
            "playbook_count": len(playbooks),
            "playbooks": [p.to_dict() for p in playbooks],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def ansible_inventory(host: str = None) -> str:
    """
    Get Ansible inventory information.

    Args:
        host: Specific host to get info for (optional, returns all if not specified)

    Returns:
        JSON with inventory data including hosts and groups

    Examples:
        ansible_inventory()  # Full inventory
        ansible_inventory(host="R1")  # Specific host vars
    """
    from core.ansible_manager import get_ansible

    try:
        ansible = get_ansible()
        inventory = ansible.get_inventory(host=host)

        return json.dumps(inventory, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def ansible_summary() -> str:
    """
    Get Ansible configuration summary.

    Shows Ansible status, available playbooks, and inventory statistics.

    Returns:
        JSON with Ansible summary including version, playbooks, and host counts
    """
    from core.ansible_manager import get_ansible

    try:
        ansible = get_ansible()
        summary = ansible.get_summary()

        return json.dumps(summary, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def ansible_adhoc(
    hosts: str,
    module: str,
    args: str = None,
    become: bool = False,
) -> str:
    """
    Run an ad-hoc Ansible command.

    Args:
        hosts: Host pattern (e.g., "R1", "cisco_routers", "all")
        module: Ansible module name (e.g., "cisco.ios.ios_command", "ping")
        args: Module arguments (e.g., "commands='show version'")
        become: Use privilege escalation

    Returns:
        JSON with command output

    Examples:
        ansible_adhoc("cisco_routers", "cisco.ios.ios_command", "commands='show clock'")
        ansible_adhoc("linux_hosts", "ping")
        ansible_adhoc("R1", "cisco.ios.ios_facts")
    """
    from core.ansible_manager import get_ansible
    from core.feature_flags import is_enabled

    if not is_enabled("use_ansible"):
        return json.dumps({
            "error": "Ansible is disabled",
            "hint": "Set FF_USE_ANSIBLE=true to enable",
        }, indent=2)

    try:
        ansible = get_ansible()
        result = ansible.run_adhoc(
            hosts=hosts,
            module=module,
            args=args,
            become=become,
        )

        return json.dumps({
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "elapsed_time": round(result.elapsed_time, 2),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    # Nornir tools (4)
    {"fn": nornir_run_command, "name": "nornir_run_command", "category": "orchestration"},
    {"fn": nornir_run_config, "name": "nornir_run_config", "category": "orchestration"},
    {"fn": nornir_get_facts, "name": "nornir_get_facts", "category": "orchestration"},
    {"fn": nornir_inventory, "name": "nornir_inventory", "category": "orchestration"},
    # Ansible tools (5)
    {"fn": ansible_run_playbook, "name": "ansible_run_playbook", "category": "orchestration"},
    {"fn": ansible_list_playbooks, "name": "ansible_list_playbooks", "category": "orchestration"},
    {"fn": ansible_inventory, "name": "ansible_inventory", "category": "orchestration"},
    {"fn": ansible_summary, "name": "ansible_summary", "category": "orchestration"},
    {"fn": ansible_adhoc, "name": "ansible_adhoc", "category": "orchestration"},
]
