"""
Containerlab device operations and provisioning.

Consolidates containerlab functionality previously duplicated in:
- network_mcp_async.py
- dashboard/api_server.py

Usage:
    from core.containerlab import run_command, check_health

    # Run a command on a containerlab device
    output = run_command("edge1", "show ip route")

    # Check health (returns dict with full info)
    health = check_health("edge1")
    print(health["status"])  # "healthy" or "critical"

    # Check health (returns just status string)
    status = check_health_status("edge1")
    print(status)  # "healthy" or "critical"

    # Provisioning functions (Phase 2)
    from core.containerlab import get_topology, list_available_images

    # Get current lab topology
    topology = get_topology()
    print(topology["nodes"])

    # List available container images
    images = list_available_images()
    print(images)
"""

import json
import logging
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Shell metacharacters that must never appear in user-supplied commands
# interpolated into shell strings (subprocess via bash -c).
_DANGEROUS_SHELL_CHARS = [';', '&&', '||', '|', '`', '$(', '${', '>', '<', '\x00']
_DANGEROUS_SHELL_SINGLES = ['"', "'"]

# Valid container name pattern (Docker naming rules)
_CONTAINER_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$')


def validate_container_name(name: str) -> tuple[bool, str]:
    """
    Validate a Docker container name.

    Returns (True, "") if valid, or (False, reason) if invalid.
    """
    if not name:
        return False, "Container name cannot be empty"
    if not _CONTAINER_NAME_RE.match(name):
        return False, f"Invalid container name: {name!r}"
    return True, ""


def _validate_shell_safe(value: str) -> tuple[bool, str]:
    """
    Reject strings containing shell metacharacters.

    Returns (True, "") if safe, or (False, reason) if dangerous.
    """
    for char in _DANGEROUS_SHELL_CHARS:
        if char in value:
            return False, f"Blocked shell character/sequence: {char!r}"
    for char in _DANGEROUS_SHELL_SINGLES:
        if char in value:
            return False, f"Blocked shell character: {char!r}"
    return True, ""

# Lazy imports to avoid circular dependency
# config/devices.py imports config/netbox_client.py which imports core/circuit_breaker.py
# core/__init__.py imports this module, causing circular import if we import at module level
_devices_cache = None
_containerlab_vm_cache = None


def _get_devices() -> dict:
    """Lazy load DEVICES dict to avoid circular import."""
    global _devices_cache
    if _devices_cache is None:
        from config.devices import DEVICES
        _devices_cache = DEVICES
    return _devices_cache


def _get_containerlab_vm() -> str:
    """Lazy load CONTAINERLAB_VM to avoid circular import."""
    global _containerlab_vm_cache
    if _containerlab_vm_cache is None:
        from config.devices import CONTAINERLAB_VM
        _containerlab_vm_cache = CONTAINERLAB_VM
    return _containerlab_vm_cache

# Topology file path (can be overridden by env var)
CONTAINERLAB_TOPOLOGY_PATH = os.getenv(
    "CONTAINERLAB_TOPOLOGY_PATH",
    "/home/ubuntu/datacenter/datacenter.clab.yml"
)


def run_command(device_name: str, command: str, timeout: int = 60) -> str:
    """
    Run a command on a containerlab device via multipass + docker exec.

    Args:
        device_name: Name of the containerlab device (e.g., "edge1", "spine1")
        command: Command to execute on the device
        timeout: Command timeout in seconds (default 60)

    Returns:
        Command output or error message
    """
    # Validate command for shell injection before any interpolation
    safe, reason = _validate_shell_safe(command)
    if not safe:
        return f"Error: Command blocked - {reason}"

    devices = _get_devices()
    device = devices.get(device_name)
    if not device:
        return f"Error: Device '{device_name}' not found"

    container = device.get("container")
    device_type = device.get("device_type")

    if not container:
        return f"Error: No container defined for {device_name}"

    valid, reason = validate_container_name(container)
    if not valid:
        return f"Error: {reason}"

    # Build the docker exec command based on device type
    if device_type == "containerlab_frr":
        if command.startswith("show ") or command.startswith("conf"):
            docker_cmd = f'sudo docker exec {container} vtysh -c "{command}"'
        else:
            docker_cmd = f'sudo docker exec {container} {command}'
    elif device_type == "containerlab_srlinux":
        docker_cmd = f'sudo docker exec {container} sr_cli "{command}"'
    else:
        # Generic containerlab device (alpine, etc.)
        docker_cmd = f'sudo docker exec {container} {command}'

    try:
        result = subprocess.run(
            ["multipass", "exec", _get_containerlab_vm(), "--", "bash", "-c", docker_cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and result.stderr:
            return f"Error: {result.stderr}"
        return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {str(e)}"


def check_health(device_name: str) -> dict:
    """
    Check health of a containerlab device.

    Args:
        device_name: Name of the containerlab device

    Returns:
        Dict with keys: device, container, status, and optionally error
    """
    devices = _get_devices()
    device = devices.get(device_name)
    if not device:
        return {
            "device": device_name,
            "container": None,
            "status": "critical",
            "error": f"Device '{device_name}' not found",
        }

    container = device.get("container")
    if not container:
        return {
            "device": device_name,
            "container": None,
            "status": "critical",
            "error": "No container defined",
        }

    valid, reason = validate_container_name(container)
    if not valid:
        return {
            "device": device_name,
            "container": container,
            "status": "critical",
            "error": reason,
        }

    result = {"device": device_name, "container": container, "status": "unknown"}

    try:
        check_cmd = f"sudo docker inspect -f '{{{{.State.Running}}}}' {container}"
        proc = subprocess.run(
            ["multipass", "exec", _get_containerlab_vm(), "--", "bash", "-c", check_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        logger.debug(f"Container health check for {device_name}: stdout={proc.stdout!r}, stderr={proc.stderr!r}, rc={proc.returncode}")
        if "true" in proc.stdout.lower():
            result["status"] = "healthy"
        else:
            result["status"] = "critical"
            result["error"] = f"Container not running: {proc.stdout.strip() or proc.stderr.strip() or 'no output'}"
    except Exception as e:
        result["status"] = "critical"
        result["error"] = str(e)
        logger.warning(f"Container health check failed for {device_name}: {e}")

    return result


def check_health_status(device_name: str) -> str:
    """
    Check health of a containerlab device, returning just the status string.

    This is a convenience function for cases where only the status is needed.

    Args:
        device_name: Name of the containerlab device

    Returns:
        Status string: "healthy" or "critical"
    """
    return check_health(device_name).get("status", "critical")


async def get_containerlab_command_output(device_name: str, command: str) -> str:
    """
    Async wrapper for running commands on containerlab devices.

    Used by core/lldp.py for LLDP discovery on containerlab devices.

    Args:
        device_name: Name of the containerlab device
        command: Command to execute

    Returns:
        Command output string
    """
    import asyncio
    # Run sync function in executor to avoid blocking
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, run_command, device_name, command)


def get_container_stats(device_name: str) -> Optional[dict]:
    """
    Get container resource stats (CPU, memory) for a containerlab device.

    Args:
        device_name: Name of the containerlab device

    Returns:
        Dict with cpu_percent, memory_usage, memory_limit, or None on error
    """
    devices = _get_devices()
    device = devices.get(device_name)
    if not device:
        return None

    container = device.get("container")
    if not container:
        return None

    valid, reason = validate_container_name(container)
    if not valid:
        return None

    try:
        # Get container stats in JSON format
        stats_cmd = (
            f"sudo docker stats {container} --no-stream "
            f"--format '{{{{.CPUPerc}}}} {{{{.MemUsage}}}}'"
        )
        proc = subprocess.run(
            ["multipass", "exec", _get_containerlab_vm(), "--", "bash", "-c", stats_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parts = proc.stdout.strip().split()
            if len(parts) >= 3:
                return {
                    "cpu_percent": parts[0].rstrip("%"),
                    "memory_usage": parts[1],
                    "memory_limit": parts[3] if len(parts) > 3 else "unknown",
                }
    except Exception:
        pass

    return None


# =============================================================================
# Provisioning Functions (Phase 2 - Read-Only)
# =============================================================================


class ContainerlabError(Exception):
    """Base exception for containerlab operations."""
    pass


class ContainerlabConnectionError(ContainerlabError):
    """Cannot connect to containerlab VM."""
    pass


class ContainerlabTopologyError(ContainerlabError):
    """Topology file operation failed."""
    pass


def _run_multipass_command(
    command: str,
    timeout: int = 30,
    correlation_id: str = "",
    stdin_data: str = None,
) -> subprocess.CompletedProcess:
    """
    Run a command on the containerlab VM via multipass.

    Args:
        command: Shell command to execute
        timeout: Command timeout in seconds
        correlation_id: For log tracing
        stdin_data: Optional data to pipe to command's stdin

    Returns:
        CompletedProcess with stdout, stderr, returncode

    Raises:
        ContainerlabConnectionError: Cannot connect to VM
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""

    try:
        result = subprocess.run(
            ["multipass", "exec", _get_containerlab_vm(), "--", "bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_data,
        )
        return result
    except subprocess.TimeoutExpired:
        raise ContainerlabConnectionError(
            f"{log_prefix}Timeout connecting to containerlab VM after {timeout}s"
        )
    except FileNotFoundError:
        raise ContainerlabConnectionError(
            f"{log_prefix}Multipass not found - is it installed?"
        )
    except Exception as e:
        raise ContainerlabConnectionError(f"{log_prefix}Failed to connect: {e}")


def is_vm_running(correlation_id: str = "") -> bool:
    """
    Check if the containerlab VM is running.

    Args:
        correlation_id: For log tracing

    Returns:
        True if VM is running, False otherwise
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    vm_name = _get_containerlab_vm()

    try:
        result = subprocess.run(
            ["multipass", "info", vm_name, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            info = json.loads(result.stdout)
            state = info.get("info", {}).get(vm_name, {}).get("state", "")
            return state.lower() == "running"
    except Exception as e:
        logger.warning(f"{log_prefix}Failed to check VM status: {e}")

    return False


def get_topology(
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Parse and return the current containerlab topology.

    Reads the YAML topology file from the VM and returns its structure.

    Args:
        topology_path: Path to topology file (default: CONTAINERLAB_TOPOLOGY_PATH)
        correlation_id: For log tracing

    Returns:
        Dict with keys: name, nodes, links, mgmt (if present)

    Raises:
        ContainerlabTopologyError: Cannot read or parse topology
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    logger.info(f"{log_prefix}Reading topology from {path}")

    try:
        # Read the YAML file from the VM
        result = _run_multipass_command(f"cat {shlex.quote(path)}", timeout=15, correlation_id=correlation_id)

        if result.returncode != 0:
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to read topology file: {result.stderr}"
            )

        # Parse YAML
        try:
            import yaml
        except ImportError:
            raise ContainerlabTopologyError(
                f"{log_prefix}PyYAML not installed - cannot parse topology"
            )

        topology = yaml.safe_load(result.stdout)

        if not topology:
            raise ContainerlabTopologyError(f"{log_prefix}Empty or invalid topology file")

        # Extract key components
        parsed = {
            "name": topology.get("name", "unknown"),
            "prefix": topology.get("prefix", ""),
            "nodes": {},
            "links": topology.get("topology", {}).get("links", []),
            "raw": topology,
        }

        # Parse nodes
        for node_name, node_config in topology.get("topology", {}).get("nodes", {}).items():
            parsed["nodes"][node_name] = {
                "name": node_name,
                "kind": node_config.get("kind", "linux"),
                "image": node_config.get("image", ""),
                "startup_config": node_config.get("startup-config"),
                "binds": node_config.get("binds", []),
                "ports": node_config.get("ports", []),
                "env": node_config.get("env", {}),
            }

        logger.info(f"{log_prefix}Parsed topology with {len(parsed['nodes'])} nodes")
        return parsed

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Failed to parse topology: {e}")


def get_existing_node_names(correlation_id: str = "") -> List[str]:
    """
    Get list of node names currently in the topology.

    Args:
        correlation_id: For log tracing

    Returns:
        List of node names
    """
    try:
        topology = get_topology(correlation_id=correlation_id)
        return list(topology.get("nodes", {}).keys())
    except ContainerlabError:
        return []


def get_running_containers(correlation_id: str = "") -> List[Dict[str, str]]:
    """
    Get list of running containerlab containers.

    Uses 'containerlab inspect' if available, falls back to docker ps.

    Args:
        correlation_id: For log tracing

    Returns:
        List of dicts with name, image, status
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    containers = []

    try:
        # Try containerlab inspect first (more accurate)
        result = _run_multipass_command(
            "cd /home/ubuntu/datacenter && sudo containerlab inspect --format json 2>/dev/null",
            timeout=20,
            correlation_id=correlation_id,
        )

        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                for container in data.get("containers", []):
                    containers.append({
                        "name": container.get("name", ""),
                        "image": container.get("image", ""),
                        "status": container.get("state", "unknown"),
                        "lab": container.get("labPath", ""),
                    })
                return containers
            except json.JSONDecodeError:
                pass

        # Fallback to docker ps with clab prefix filter
        result = _run_multipass_command(
            "sudo docker ps --filter 'name=clab-' --format '{{.Names}}|{{.Image}}|{{.Status}}'",
            timeout=15,
            correlation_id=correlation_id,
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        containers.append({
                            "name": parts[0],
                            "image": parts[1],
                            "status": parts[2],
                        })

    except ContainerlabError as e:
        logger.warning(f"{log_prefix}Failed to list containers: {e}")

    return containers


def list_available_images(correlation_id: str = "") -> List[Dict[str, str]]:
    """
    List container images available for containerlab nodes.

    Queries Docker on the VM for available images, filtering to
    commonly used containerlab images.

    Args:
        correlation_id: For log tracing

    Returns:
        List of dicts with repository, tag, size

    Example:
        [
            {"repository": "ghcr.io/nokia/srlinux", "tag": "24.7.1", "size": "2.1GB"},
            {"repository": "frrouting/frr", "tag": "v10.2.1", "size": "250MB"},
            {"repository": "alpine", "tag": "latest", "size": "8MB"},
        ]
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    images = []

    # Known containerlab image patterns
    clab_image_patterns = [
        "nokia", "srlinux",
        "frrouting", "frr",
        "alpine",
        "ceos", "arista",
        "vrnetlab",
        "networkop",
    ]

    try:
        result = _run_multipass_command(
            "sudo docker images --format '{{.Repository}}|{{.Tag}}|{{.Size}}'",
            timeout=15,
            correlation_id=correlation_id,
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        repo = parts[0]
                        # Filter to known containerlab images
                        if any(pattern in repo.lower() for pattern in clab_image_patterns):
                            images.append({
                                "repository": repo,
                                "tag": parts[1],
                                "size": parts[2],
                            })

        # Sort by repository name
        images.sort(key=lambda x: x["repository"])
        logger.info(f"{log_prefix}Found {len(images)} containerlab images")

    except ContainerlabError as e:
        logger.warning(f"{log_prefix}Failed to list images: {e}")

    return images


def validate_node_name(name: str, correlation_id: str = "") -> Dict[str, Any]:
    """
    Validate a proposed node name for containerlab.

    Checks:
    - Name follows containerlab naming conventions
    - Name is not already in use
    - Name doesn't conflict with reserved names

    Args:
        name: Proposed node name
        correlation_id: For log tracing

    Returns:
        Dict with valid (bool), reason (str if invalid)

    Example:
        >>> validate_node_name("R10")
        {"valid": True}
        >>> validate_node_name("edge1")
        {"valid": False, "reason": "Node 'edge1' already exists in topology"}
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""

    # Check naming conventions
    if not name:
        return {"valid": False, "reason": "Node name cannot be empty"}

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", name):
        return {
            "valid": False,
            "reason": "Node name must start with a letter and contain only letters, numbers, underscores, and hyphens",
        }

    if len(name) > 50:
        return {"valid": False, "reason": "Node name must be 50 characters or less"}

    # Check for reserved names
    reserved_names = {"host", "bridge", "mgmt", "docker", "clab", "containerlab"}
    if name.lower() in reserved_names:
        return {"valid": False, "reason": f"'{name}' is a reserved name"}

    # Check if name exists in topology
    try:
        existing = get_existing_node_names(correlation_id)
        if name in existing:
            return {"valid": False, "reason": f"Node '{name}' already exists in topology"}
    except ContainerlabError as e:
        logger.warning(f"{log_prefix}Could not check existing nodes: {e}")
        # Continue validation - we'll catch conflicts during provisioning

    return {"valid": True}


def get_node_kinds() -> List[Dict[str, str]]:
    """
    Get list of supported containerlab node kinds with descriptions.

    Returns:
        List of dicts with kind, description, default_image
    """
    return [
        {
            "kind": "nokia_srlinux",
            "description": "Nokia SR Linux",
            "default_image": "ghcr.io/nokia/srlinux:latest",
        },
        {
            "kind": "linux",
            "description": "Generic Linux container",
            "default_image": "alpine:latest",
        },
        {
            "kind": "frr",
            "description": "FRRouting container",
            "default_image": "quay.io/frrouting/frr:latest",
        },
        {
            "kind": "ceos",
            "description": "Arista cEOS",
            "default_image": "ceos:latest",
        },
        {
            "kind": "vr-ros",
            "description": "MikroTik RouterOS (vrnetlab)",
            "default_image": "vrnetlab/ros:latest",
        },
        {
            "kind": "vr-sros",
            "description": "Nokia SR OS (vrnetlab)",
            "default_image": "vrnetlab/sros:latest",
        },
    ]


# =============================================================================
# Provisioning Functions (Phase 4 - Write Operations)
# =============================================================================


def _backup_topology(
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> str:
    """
    Create a timestamped backup of the topology file.

    Args:
        topology_path: Path to topology file (default: CONTAINERLAB_TOPOLOGY_PATH)
        correlation_id: For log tracing

    Returns:
        Path to backup file on the VM

    Raises:
        ContainerlabTopologyError: Cannot create backup
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    # Create backup filename with timestamp
    from core.timestamps import now
    timestamp = now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{path}.backup.{timestamp}"

    logger.info(f"{log_prefix}Creating topology backup at {backup_path}")

    try:
        result = _run_multipass_command(
            f"cp {shlex.quote(path)} {shlex.quote(backup_path)}",
            timeout=15,
            correlation_id=correlation_id,
        )

        if result.returncode != 0:
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to create backup: {result.stderr}"
            )

        logger.info(f"{log_prefix}Backup created successfully")
        return backup_path

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Backup failed: {e}")


def _restore_topology(
    backup_path: str,
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> bool:
    """
    Restore topology from a backup file.

    Args:
        backup_path: Path to backup file on VM
        topology_path: Path to topology file (default: CONTAINERLAB_TOPOLOGY_PATH)
        correlation_id: For log tracing

    Returns:
        True if restored successfully

    Raises:
        ContainerlabTopologyError: Cannot restore backup
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    logger.info(f"{log_prefix}Restoring topology from {backup_path}")

    try:
        result = _run_multipass_command(
            f"cp {shlex.quote(backup_path)} {shlex.quote(path)}",
            timeout=15,
            correlation_id=correlation_id,
        )

        if result.returncode != 0:
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to restore backup: {result.stderr}"
            )

        logger.info(f"{log_prefix}Topology restored successfully")
        return True

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Restore failed: {e}")


def add_node(
    name: str,
    kind: str,
    image: Optional[str] = None,
    startup_config: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Add a new node to the containerlab topology.

    IMPORTANT: This modifies the topology YAML but does NOT deploy.
    Call deploy_topology() after adding nodes to apply changes.

    Steps:
    1. Validate node name
    2. Create backup of topology
    3. Parse existing topology
    4. Add new node definition
    5. Write updated topology

    Args:
        name: Node name (must be unique)
        kind: Node kind (nokia_srlinux, frr, linux, etc.)
        image: Container image (uses kind default if not provided)
        startup_config: Path to startup config file (optional)
        env: Environment variables dict (optional)
        topology_path: Path to topology file (default: CONTAINERLAB_TOPOLOGY_PATH)
        correlation_id: For log tracing

    Returns:
        Dict with:
            - success: bool
            - backup_path: str (for rollback)
            - node: dict (node definition added)

    Raises:
        ContainerlabTopologyError: Cannot modify topology
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    # Validate name
    validation = validate_node_name(name, correlation_id)
    if not validation.get("valid"):
        raise ContainerlabTopologyError(
            f"{log_prefix}Invalid node name: {validation.get('reason')}"
        )

    # Get default image for kind if not provided
    if not image:
        for kind_info in get_node_kinds():
            if kind_info["kind"] == kind:
                image = kind_info["default_image"]
                break
        else:
            image = "alpine:latest"  # Fallback

    logger.info(f"{log_prefix}Adding node '{name}' (kind={kind}, image={image})")

    try:
        # Create backup
        backup_path = _backup_topology(path, correlation_id)

        # Get current topology
        topology = get_topology(path, correlation_id)

        # Build node definition
        node_def = {
            "kind": kind,
            "image": image,
        }
        if startup_config:
            node_def["startup-config"] = startup_config
        if env:
            node_def["env"] = env

        # Add to raw topology
        raw = topology.get("raw", {})
        if "topology" not in raw:
            raw["topology"] = {}
        if "nodes" not in raw["topology"]:
            raw["topology"]["nodes"] = {}

        raw["topology"]["nodes"][name] = node_def

        # Convert back to YAML
        try:
            import yaml
        except ImportError:
            raise ContainerlabTopologyError(
                f"{log_prefix}PyYAML not installed"
            )

        yaml_content = yaml.dump(raw, default_flow_style=False, sort_keys=False)

        # Write updated topology to VM via stdin (avoids heredoc delimiter collision)
        write_cmd = f"cat > {shlex.quote(path)}"
        result = _run_multipass_command(
            write_cmd,
            timeout=15,
            correlation_id=correlation_id,
            stdin_data=yaml_content,
        )

        if result.returncode != 0:
            # Restore backup on failure
            _restore_topology(backup_path, path, correlation_id)
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to write topology: {result.stderr}"
            )

        logger.info(f"{log_prefix}Node '{name}' added to topology")

        return {
            "success": True,
            "backup_path": backup_path,
            "node": {
                "name": name,
                **node_def,
            },
        }

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Failed to add node: {e}")


def remove_node_from_topology(
    name: str,
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Remove a node from the topology YAML.

    IMPORTANT: This only modifies the YAML file. Use destroy_node() to
    actually remove a running container.

    Args:
        name: Node name to remove
        topology_path: Path to topology file
        correlation_id: For log tracing

    Returns:
        Dict with success, backup_path

    Raises:
        ContainerlabTopologyError: Cannot modify topology
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    logger.info(f"{log_prefix}Removing node '{name}' from topology")

    try:
        # Create backup
        backup_path = _backup_topology(path, correlation_id)

        # Get current topology
        topology = get_topology(path, correlation_id)
        raw = topology.get("raw", {})

        # Check if node exists
        nodes = raw.get("topology", {}).get("nodes", {})
        if name not in nodes:
            raise ContainerlabTopologyError(
                f"{log_prefix}Node '{name}' not found in topology"
            )

        # Remove node
        del raw["topology"]["nodes"][name]

        # Remove any links involving this node
        links = raw.get("topology", {}).get("links", [])
        new_links = []
        for link in links:
            endpoints = link.get("endpoints", [])
            # Check if any endpoint starts with the node name
            involves_node = any(
                ep.startswith(f"{name}:") for ep in endpoints
            )
            if not involves_node:
                new_links.append(link)

        if "links" in raw.get("topology", {}):
            raw["topology"]["links"] = new_links

        # Write updated topology
        try:
            import yaml
        except ImportError:
            raise ContainerlabTopologyError(f"{log_prefix}PyYAML not installed")

        yaml_content = yaml.dump(raw, default_flow_style=False, sort_keys=False)
        write_cmd = f"cat > {shlex.quote(path)}"
        result = _run_multipass_command(
            write_cmd,
            timeout=15,
            correlation_id=correlation_id,
            stdin_data=yaml_content,
        )

        if result.returncode != 0:
            _restore_topology(backup_path, path, correlation_id)
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to write topology: {result.stderr}"
            )

        logger.info(f"{log_prefix}Node '{name}' removed from topology")

        return {
            "success": True,
            "backup_path": backup_path,
        }

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Failed to remove node: {e}")


def deploy_topology(
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Deploy the containerlab topology.

    IMPORTANT: Uses 'containerlab deploy' which is ADDITIVE.
    This will start any new nodes without disrupting existing ones.
    DO NOT use --reconfigure which destroys the entire lab.

    Args:
        topology_path: Path to topology file
        correlation_id: For log tracing

    Returns:
        Dict with success, output

    Raises:
        ContainerlabTopologyError: Deployment failed
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    # Get the directory containing the topology file
    topo_dir = os.path.dirname(path)

    logger.info(f"{log_prefix}Deploying topology from {path}")

    try:
        # CRITICAL: Use 'deploy' WITHOUT --reconfigure
        # --reconfigure destroys the entire lab and recreates it
        result = _run_multipass_command(
            f"cd {shlex.quote(topo_dir)} && sudo containerlab deploy -t {shlex.quote(path)}",
            timeout=300,  # 5 minute timeout for deployment
            correlation_id=correlation_id,
        )

        if result.returncode != 0:
            raise ContainerlabTopologyError(
                f"{log_prefix}Deployment failed: {result.stderr}"
            )

        logger.info(f"{log_prefix}Deployment completed successfully")

        return {
            "success": True,
            "output": result.stdout,
        }

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Deployment failed: {e}")


def destroy_node(
    name: str,
    lab_name: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Destroy a single node without affecting the rest of the lab.

    Uses containerlab's node filter to target only the specified node.

    Args:
        name: Node name to destroy
        lab_name: Lab name (default: from topology)
        correlation_id: For log tracing

    Returns:
        Dict with success, output

    Raises:
        ContainerlabTopologyError: Destroy failed
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""

    # Get lab name from topology if not provided
    if not lab_name:
        try:
            topology = get_topology(correlation_id=correlation_id)
            lab_name = topology.get("name", "datacenter")
        except ContainerlabError:
            lab_name = "datacenter"

    # Validate node name before shell interpolation
    valid, reason = validate_container_name(name)
    if not valid:
        raise ContainerlabTopologyError(f"Invalid node name: {reason}")

    # Build container name (clab-<lab>-<node>)
    container_name = f"clab-{lab_name}-{name}"

    logger.info(f"{log_prefix}Destroying node '{name}' (container: {container_name})")

    try:
        # Stop and remove the container
        result = _run_multipass_command(
            f"sudo docker rm -f {shlex.quote(container_name)}",
            timeout=60,
            correlation_id=correlation_id,
        )

        if result.returncode != 0 and "No such container" not in result.stderr:
            raise ContainerlabTopologyError(
                f"{log_prefix}Failed to destroy container: {result.stderr}"
            )

        logger.info(f"{log_prefix}Node '{name}' destroyed")

        return {
            "success": True,
            "output": result.stdout,
        }

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(f"{log_prefix}Destroy failed: {e}")


def provision_node(
    name: str,
    kind: str,
    image: Optional[str] = None,
    startup_config: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Full node provisioning: add to topology and deploy.

    This is the main function for adding a new containerlab node.
    It combines add_node() and deploy_topology() with proper
    error handling and rollback.

    Args:
        name: Node name
        kind: Node kind
        image: Container image (optional)
        startup_config: Startup config path (optional)
        env: Environment variables (optional)
        topology_path: Topology file path (optional)
        correlation_id: For log tracing

    Returns:
        Dict with:
            - success: bool
            - node: dict (node definition)
            - backup_path: str (for manual rollback if needed)
            - container_name: str

    Raises:
        ContainerlabTopologyError: Provisioning failed
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    logger.info(f"{log_prefix}Starting full provisioning for node '{name}'")

    backup_path = None
    try:
        # Step 1: Add node to topology
        add_result = add_node(
            name=name,
            kind=kind,
            image=image,
            startup_config=startup_config,
            env=env,
            topology_path=path,
            correlation_id=correlation_id,
        )
        backup_path = add_result.get("backup_path")

        # Step 2: Deploy topology
        deploy_result = deploy_topology(
            topology_path=path,
            correlation_id=correlation_id,
        )

        # Get lab name for container name
        topology = get_topology(path, correlation_id)
        lab_name = topology.get("name", "datacenter")
        container_name = f"clab-{lab_name}-{name}"

        logger.info(f"{log_prefix}Node '{name}' provisioned successfully")

        return {
            "success": True,
            "node": add_result.get("node"),
            "backup_path": backup_path,
            "container_name": container_name,
            "deploy_output": deploy_result.get("output"),
        }

    except ContainerlabError as e:
        # Rollback on failure
        if backup_path:
            logger.warning(f"{log_prefix}Provisioning failed, rolling back")
            try:
                _restore_topology(backup_path, path, correlation_id)
            except Exception as rollback_error:
                logger.error(f"{log_prefix}Rollback failed: {rollback_error}")

        raise ContainerlabTopologyError(
            f"{log_prefix}Provisioning failed: {e}"
        )


def deprovision_node(
    name: str,
    topology_path: Optional[str] = None,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """
    Full node deprovisioning: destroy container and remove from topology.

    Args:
        name: Node name to remove
        topology_path: Topology file path
        correlation_id: For log tracing

    Returns:
        Dict with success, backup_path

    Raises:
        ContainerlabTopologyError: Deprovisioning failed
    """
    log_prefix = f"[{correlation_id}] " if correlation_id else ""
    path = topology_path or CONTAINERLAB_TOPOLOGY_PATH

    logger.info(f"{log_prefix}Starting deprovisioning for node '{name}'")

    try:
        # Step 1: Destroy the container
        destroy_result = destroy_node(
            name=name,
            correlation_id=correlation_id,
        )

        # Step 2: Remove from topology
        remove_result = remove_node_from_topology(
            name=name,
            topology_path=path,
            correlation_id=correlation_id,
        )

        logger.info(f"{log_prefix}Node '{name}' deprovisioned successfully")

        return {
            "success": True,
            "backup_path": remove_result.get("backup_path"),
        }

    except ContainerlabError:
        raise
    except Exception as e:
        raise ContainerlabTopologyError(
            f"{log_prefix}Deprovisioning failed: {e}"
        )
