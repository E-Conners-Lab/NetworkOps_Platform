"""
Configuration management MCP tools.

This module provides tools for configuration backup, rollback, and testing:
- backup_config: Backup running configuration to file
- compare_configs: Compare configurations between devices or files
- list_backups: List saved configuration backups
- rollback_config: Restore configuration from backup
- export_documentation: Generate device documentation
- full_network_test: Comprehensive network connectivity test
"""

import asyncio
import difflib
import json
import re
import time
from datetime import datetime
from core.timestamps import isonow, now
from pathlib import Path

from config.devices import DEVICES
from core import log_event
from core.scrapli_manager import get_ios_xe_connection
from mcp_tools._shared import throttled

# Canonical backup base directory (all backup paths must resolve within this)
BACKUP_BASE = (Path(__file__).parent.parent / "data" / "config_backups").resolve()


# =============================================================================
# Helper Functions
# =============================================================================

def _validate_path_confined(user_path: Path, allowed_base: Path) -> tuple[bool, str]:
    """
    Verify that a resolved path is inside the allowed base directory.

    Returns (True, "") if safe, or (False, reason) if the path escapes.
    """
    try:
        resolved = user_path.resolve()
    except (OSError, ValueError) as e:
        return False, f"Invalid path: {e}"
    if not str(resolved).startswith(str(allowed_base)):
        return False, "Path resolves outside the allowed backup directory"
    return True, ""


def _validate_device_name(device_name: str) -> tuple[bool, str]:
    """Reject device names containing path traversal characters."""
    if not device_name or '..' in device_name or '/' in device_name or '\\' in device_name:
        return False, "Invalid device name: contains path traversal characters"
    return True, ""


def is_cisco_device(device_name: str) -> bool:
    """Check if device is a Cisco IOS-XE device."""
    device = DEVICES.get(device_name, {})
    return device.get("device_type") == "cisco_xe"


async def _send_command_raw(device_name: str, command: str) -> tuple:
    """Send a command and return raw result tuple."""
    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command(command)
            return (device_name, command, response.result)
    except Exception as e:
        return (device_name, command, f"Error: {str(e)}")


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def backup_config(device_name: str, label: str = None) -> str:
    """
    Backup running configuration from a device to a local file.

    Args:
        device_name: Device to backup
        label: Optional label for the backup (default: timestamp)

    Returns:
        JSON with backup file path and metadata
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Config backup only supported for IOS-XE devices"})

    # Create backups directory
    backup_dir = Path(__file__).parent.parent / "data" / "config_backups" / device_name
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename
    timestamp = now().strftime("%Y%m%d_%H%M%S")
    if label:
        # Validate label for path traversal characters
        if '..' in label or '/' in label or '\\' in label:
            return json.dumps({"error": "Backup label contains invalid path characters"})
        filename = f"{device_name}_{label}_{timestamp}.cfg"
    else:
        filename = f"{device_name}_{timestamp}.cfg"
    backup_path = backup_dir / filename

    try:
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command("show running-config")
            config = response.result

        # Write config to file
        backup_path.write_text(config)

        log_event("backup_config", device_name, f"Saved to {filename}", "success", "operator")

        return json.dumps({
            "status": "success",
            "device": device_name,
            "file": str(backup_path),
            "filename": filename,
            "size_bytes": len(config),
            "lines": len(config.splitlines()),
            "timestamp": timestamp
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


async def compare_configs(device1: str, device2: str = None, file1: str = None, file2: str = None) -> str:
    """
    Compare configurations between devices or backup files.

    Usage modes:
    - compare_configs(device1, device2): Compare running configs of two devices
    - compare_configs(device1, file2=path): Compare device running config to backup file
    - compare_configs(file1=path1, file2=path2): Compare two backup files

    Returns:
        JSON with diff summary and changed lines
    """
    config1 = None
    config2 = None
    source1 = ""
    source2 = ""

    # Get first config
    if device1 and device1 in DEVICES:
        if is_cisco_device(device1):
            try:
                async with get_ios_xe_connection(device1) as conn:
                    response = await conn.send_command("show running-config")
                    config1 = response.result
                    source1 = f"{device1} (running)"
            except Exception as e:
                return json.dumps({"error": f"Failed to get config from {device1}: {e}"})
        else:
            return json.dumps({"error": "Config comparison only supported for IOS-XE devices"})
    elif file1:
        path1 = Path(file1)
        safe, reason = _validate_path_confined(path1, BACKUP_BASE)
        if not safe:
            return json.dumps({"error": f"File path rejected: {reason}"})
        if path1.exists():
            config1 = path1.read_text()
            source1 = str(path1)
        else:
            return json.dumps({"error": f"File not found: {file1}"})
    else:
        return json.dumps({"error": "Must provide device1 or file1"})

    # Get second config
    if device2 and device2 in DEVICES:
        if is_cisco_device(device2):
            try:
                async with get_ios_xe_connection(device2) as conn:
                    response = await conn.send_command("show running-config")
                    config2 = response.result
                    source2 = f"{device2} (running)"
            except Exception as e:
                return json.dumps({"error": f"Failed to get config from {device2}: {e}"})
        else:
            return json.dumps({"error": "Config comparison only supported for IOS-XE devices"})
    elif file2:
        path2 = Path(file2)
        safe, reason = _validate_path_confined(path2, BACKUP_BASE)
        if not safe:
            return json.dumps({"error": f"File path rejected: {reason}"})
        if path2.exists():
            config2 = path2.read_text()
            source2 = str(path2)
        else:
            return json.dumps({"error": f"File not found: {file2}"})
    else:
        return json.dumps({"error": "Must provide device2 or file2"})

    # Compute diff
    lines1 = config1.splitlines()
    lines2 = config2.splitlines()

    diff = list(difflib.unified_diff(lines1, lines2, fromfile=source1, tofile=source2, lineterm=''))

    # Analyze changes
    added = [line[1:] for line in diff if line.startswith('+') and not line.startswith('+++')]
    removed = [line[1:] for line in diff if line.startswith('-') and not line.startswith('---')]

    log_event("compare_configs", None, f"Compared {source1} vs {source2}", "success", "operator")

    return json.dumps({
        "source1": source1,
        "source2": source2,
        "summary": {
            "lines_added": len(added),
            "lines_removed": len(removed),
            "identical": len(diff) == 0
        },
        "added": added[:50],  # Limit output size
        "removed": removed[:50],
        "diff": diff[:200] if diff else ["No differences found"]
    }, indent=2)


async def list_backups(device_name: str = None) -> str:
    """
    List saved configuration backups.

    Args:
        device_name: Optional device name to filter (shows all if not specified)

    Returns:
        JSON with backup file list and metadata
    """
    backup_base = Path(__file__).parent.parent / "data" / "config_backups"

    if not backup_base.exists():
        return json.dumps({
            "total_backups": 0,
            "backups": [],
            "message": "No backups found"
        }, indent=2)

    backups = []

    if device_name:
        # Validate device name against path traversal
        valid, reason = _validate_device_name(device_name)
        if not valid:
            return json.dumps({"error": reason})

        # List backups for specific device
        device_dir = backup_base / device_name
        if device_dir.exists():
            for backup_file in sorted(device_dir.glob("*.cfg"), reverse=True):
                stat = backup_file.stat()
                backups.append({
                    "device": device_name,
                    "filename": backup_file.name,
                    "path": str(backup_file),
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
    else:
        # List all backups
        for device_dir in sorted(backup_base.iterdir()):
            if device_dir.is_dir():
                for backup_file in sorted(device_dir.glob("*.cfg"), reverse=True):
                    stat = backup_file.stat()
                    backups.append({
                        "device": device_dir.name,
                        "filename": backup_file.name,
                        "path": str(backup_file),
                        "size_bytes": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })

    # Group by device
    by_device = {}
    for backup in backups:
        dev = backup["device"]
        by_device[dev] = by_device.get(dev, 0) + 1

    return json.dumps({
        "filter_device": device_name,
        "total_backups": len(backups),
        "by_device": by_device,
        "backups": backups[:50]  # Limit output
    }, indent=2)


async def rollback_config(
    device_name: str,
    backup_file: str = None,
    backup_label: str = None,
    dry_run: bool = True
) -> str:
    """
    Rollback device configuration to a previous backup.

    Args:
        device_name: Device to rollback
        backup_file: Full path to backup file, OR
        backup_label: Label to search for (use "latest" for most recent backup)
        dry_run: If True (default), only show diff without applying changes

    Returns:
        JSON with diff preview and rollback status

    Examples:
        rollback_config("R1", backup_label="latest")  # Preview latest backup
        rollback_config("R1", backup_label="latest", dry_run=False)  # Apply it
        rollback_config("R1", backup_file="/path/to/backup.cfg", dry_run=False)
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Config rollback only supported for IOS-XE devices"})

    if not backup_file and not backup_label:
        return json.dumps({"error": "Must specify either backup_file or backup_label"})

    # Find the backup file
    backup_path = None
    backup_dir = Path(__file__).parent.parent / "data" / "config_backups" / device_name

    if backup_file:
        backup_path = Path(backup_file)
        safe, reason = _validate_path_confined(backup_path, BACKUP_BASE)
        if not safe:
            return json.dumps({"error": f"Backup file path rejected: path resolves outside the allowed backup directory"})
        if not backup_path.exists():
            return json.dumps({"error": f"Backup file not found: {backup_file}"})
    elif backup_label:
        if not backup_dir.exists():
            return json.dumps({"error": f"No backups found for {device_name}"})

        # Validate backup_label for path traversal
        if '..' in backup_label or '/' in backup_label or '\\' in backup_label:
            return json.dumps({"error": "Backup label contains invalid path characters"})

        if backup_label.lower() == "latest":
            # Get most recent backup
            backups = sorted(backup_dir.glob("*.cfg"), key=lambda x: x.stat().st_mtime, reverse=True)
            if not backups:
                return json.dumps({"error": f"No backups found for {device_name}"})
            backup_path = backups[0]
        else:
            # Search for matching label
            matches = list(backup_dir.glob(f"*{backup_label}*.cfg"))
            # Filter to only files inside the expected directory
            matches = [m for m in matches if str(m.resolve()).startswith(str(BACKUP_BASE))]
            if not matches:
                return json.dumps({"error": f"No backup found matching label '{backup_label}'"})
            if len(matches) > 1:
                return json.dumps({
                    "error": f"Multiple backups match '{backup_label}'",
                    "matches": [m.name for m in matches]
                })
            backup_path = matches[0]

    # Read backup config
    backup_config_content = backup_path.read_text()
    backup_lines = backup_config_content.splitlines()

    try:
        # Get current running config
        async with get_ios_xe_connection(device_name) as conn:
            response = await conn.send_command("show running-config")
            current_config = response.result

        current_lines = current_config.splitlines()

        # Generate diff
        diff = list(difflib.unified_diff(
            current_lines,
            backup_lines,
            fromfile="current_running_config",
            tofile=backup_path.name,
            lineterm=""
        ))

        # Count changes
        additions = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
        deletions = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

        if additions == 0 and deletions == 0:
            return json.dumps({
                "status": "no_changes",
                "device": device_name,
                "backup_file": backup_path.name,
                "message": "Backup config matches current running config - no rollback needed"
            }, indent=2)

        result = {
            "device": device_name,
            "backup_file": backup_path.name,
            "backup_path": str(backup_path),
            "dry_run": dry_run,
            "changes": {
                "lines_added": additions,
                "lines_removed": deletions,
                "total_changes": additions + deletions
            },
            "diff_preview": diff[:100] if len(diff) > 100 else diff,
            "diff_truncated": len(diff) > 100
        }

        if dry_run:
            result["status"] = "preview"
            result["message"] = "Dry run - no changes applied. Set dry_run=False to apply."
            result["next_step"] = f'rollback_config("{device_name}", backup_label="latest", dry_run=False)'
        else:
            # First, backup current config before rollback
            pre_rollback_timestamp = now().strftime("%Y%m%d_%H%M%S")
            pre_rollback_file = backup_dir / f"{device_name}_pre_rollback_{pre_rollback_timestamp}.cfg"
            backup_dir.mkdir(parents=True, exist_ok=True)
            pre_rollback_file.write_text(current_config)

            # Extract config commands from backup (skip headers and timestamps)
            config_lines = []
            in_config = False
            skip_patterns = [
                "Building configuration",
                "Current configuration",
                "Last configuration change",
                "NVRAM config last updated",
                "version ",
                "boot-start-marker",
                "boot-end-marker",
                "!Time:",
                "!Command:",
                "!Running configuration",
            ]

            for line in backup_lines:
                # Skip empty lines at start
                if not in_config and not line.strip():
                    continue
                # Skip header lines
                if any(line.strip().startswith(pat) for pat in skip_patterns):
                    continue
                # Start capturing after version line or first real config
                if line.strip().startswith("hostname") or line.strip().startswith("service"):
                    in_config = True
                if in_config:
                    config_lines.append(line)

            # Remove trailing 'end' if present
            if config_lines and config_lines[-1].strip() == "end":
                config_lines = config_lines[:-1]

            # Apply configuration
            async with get_ios_xe_connection(device_name) as conn:
                # Enter config mode and apply
                await conn.send_command("configure terminal")

                # Send config in chunks to avoid timeout
                chunk_size = 50
                applied_lines = 0
                errors = []

                for i in range(0, len(config_lines), chunk_size):
                    chunk = config_lines[i:i + chunk_size]
                    for line in chunk:
                        if line.strip() and not line.strip().startswith("!"):
                            try:
                                await conn.send_command(line.strip(), timeout_ops=10)
                                applied_lines += 1
                            except Exception as e:
                                errors.append({"line": line.strip(), "error": str(e)})

                # Exit config mode
                await conn.send_command("end")

            log_event(
                "rollback_config",
                device_name,
                f"Rolled back to {backup_path.name}, {applied_lines} lines applied",
                "success",
                "operator"
            )

            result["status"] = "applied"
            result["pre_rollback_backup"] = str(pre_rollback_file)
            result["lines_applied"] = applied_lines
            result["message"] = f"Rollback applied. Previous config saved to {pre_rollback_file.name}"

            if errors:
                result["warnings"] = f"{len(errors)} lines had errors"
                result["errors"] = errors[:10]  # Show first 10 errors

            result["note"] = "Config applied additively. For full replace, use 'configure replace' manually."

        return json.dumps(result, indent=2)

    except Exception as e:
        log_event("rollback_config", device_name, str(e), "error", "operator")
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


async def export_documentation(device_name: str, format: str = "markdown") -> str:
    """
    Export device documentation including interfaces, neighbors, and routes.

    Args:
        device_name: Device to document
        format: "markdown" or "json"

    Returns:
        Device documentation in requested format
    """
    if device_name not in DEVICES:
        return json.dumps({"error": f"Device '{device_name}' not found"})

    if not is_cisco_device(device_name):
        return json.dumps({"error": "Documentation export only supported for Cisco devices"})

    try:
        async with get_ios_xe_connection(device_name) as conn:
            version_output = await conn.send_command("show version")
            interfaces_output = await conn.send_command("show ip interface brief")
            cdp_output = await conn.send_command("show cdp neighbors detail")
            routes_output = await conn.send_command("show ip route summary")
            inventory_output = await conn.send_command("show inventory")

        # Parse version info
        version_match = re.search(r'Version\s+([\d\.]+\w*)', version_output.result)
        version = version_match.group(1) if version_match else "unknown"

        model_match = re.search(r'cisco\s+(\S+)', version_output.result, re.IGNORECASE)
        model = model_match.group(1) if model_match else "unknown"

        hostname_match = re.search(r'(\S+)\s+uptime is', version_output.result)
        hostname = hostname_match.group(1) if hostname_match else device_name

        uptime_match = re.search(r'uptime is\s+(.+)', version_output.result)
        uptime = uptime_match.group(1).strip() if uptime_match else "unknown"

        serial_match = re.search(r'Processor board ID\s+(\S+)', version_output.result)
        serial = serial_match.group(1) if serial_match else "unknown"

        # Parse interfaces
        interfaces = []
        for line in interfaces_output.result.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                interfaces.append({
                    "name": parts[0],
                    "ip": parts[1],
                    "status": parts[4],
                    "protocol": parts[5]
                })

        # Parse CDP neighbors
        neighbors = []
        current_neighbor = {}
        for line in cdp_output.result.splitlines():
            if "Device ID:" in line:
                if current_neighbor:
                    neighbors.append(current_neighbor)
                current_neighbor = {"device_id": line.split(":")[-1].strip()}
            elif "IP address:" in line:
                current_neighbor["ip"] = line.split(":")[-1].strip()
            elif "Platform:" in line:
                platform_match = re.search(r'Platform:\s*([^,]+)', line)
                if platform_match:
                    current_neighbor["platform"] = platform_match.group(1).strip()
            elif "Interface:" in line:
                intf_match = re.search(r'Interface:\s*(\S+)', line)
                if intf_match:
                    current_neighbor["local_interface"] = intf_match.group(1)
        if current_neighbor:
            neighbors.append(current_neighbor)

        doc = {
            "device": device_name,
            "hostname": hostname,
            "model": model,
            "version": version,
            "serial": serial,
            "uptime": uptime,
            "generated_at": isonow(),
            "interfaces": interfaces,
            "neighbors": neighbors,
            "interface_count": len(interfaces),
            "neighbor_count": len(neighbors)
        }

        if format == "json":
            return json.dumps({"status": "success", "documentation": doc}, indent=2)

        # Generate Markdown
        md = f"""# {hostname} Documentation

**Generated:** {doc['generated_at']}

## Device Information

| Property | Value |
|----------|-------|
| Hostname | {hostname} |
| Model | {model} |
| Version | {version} |
| Serial | {serial} |
| Uptime | {uptime} |

## Interfaces ({len(interfaces)})

| Interface | IP Address | Status | Protocol |
|-----------|------------|--------|----------|
"""
        for intf in interfaces:
            md += f"| {intf['name']} | {intf['ip']} | {intf['status']} | {intf['protocol']} |\n"

        md += f"\n## CDP Neighbors ({len(neighbors)})\n\n"
        md += "| Device | Platform | Local Interface | IP |\n"
        md += "|--------|----------|-----------------|----|\n"
        for n in neighbors:
            md += f"| {n.get('device_id', 'N/A')} | {n.get('platform', 'N/A')} | {n.get('local_interface', 'N/A')} | {n.get('ip', 'N/A')} |\n"

        return json.dumps({
            "status": "success",
            "format": "markdown",
            "device": device_name,
            "documentation": md
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "status": "error",
            "device": device_name,
            "error": str(e)
        }, indent=2)


async def full_network_test() -> str:
    """
    Comprehensive network connectivity test.
    Checks OSPF neighbors, BGP sessions, and DMVPN tunnels on core routers (R1-R4).
    Runs all checks in parallel for speed (~3-5 seconds).
    """
    from config.devices import LOOPBACK_MAP

    start = time.time()

    results = {
        "ospf": {},
        "bgp": {"ibgp": {}, "ebgp": {}},
        "dmvpn": {"hub": "R1", "spokes": {}},
        "ping": {},
        "summary": {"passed": 0, "failed": 0, "tests": []}
    }

    # Run all checks in parallel with throttling
    tasks = [
        # OSPF on all routers
        throttled(_send_command_raw("R1", "show ip ospf neighbor")),
        throttled(_send_command_raw("R2", "show ip ospf neighbor")),
        throttled(_send_command_raw("R3", "show ip ospf neighbor")),
        throttled(_send_command_raw("R4", "show ip ospf neighbor")),
        # BGP on R1 (route reflector) and R3 (eBGP)
        throttled(_send_command_raw("R1", "show ip bgp summary")),
        throttled(_send_command_raw("R3", "show ip bgp summary")),
        # DMVPN on R1 (hub)
        throttled(_send_command_raw("R1", "show dmvpn")),
        # Ping from R1 to other routers
        throttled(_send_command_raw("R1", f"ping {LOOPBACK_MAP.get('R2', '198.51.100.2')} repeat 2")),
        throttled(_send_command_raw("R1", f"ping {LOOPBACK_MAP.get('R3', '198.51.100.3')} repeat 2")),
        throttled(_send_command_raw("R1", f"ping {LOOPBACK_MAP.get('R4', '198.51.100.4')} repeat 2")),
    ]

    outputs = await asyncio.gather(*tasks, return_exceptions=True)

    # Helper function to check if BGP state indicates established session
    def is_bgp_established(state: str) -> bool:
        """Check if BGP state indicates established session."""
        try:
            int(state)
            return True
        except ValueError:
            pass
        if ":" in state:
            cleaned = state.replace(":", "")
            if cleaned.isdigit():
                return True
        if any(c in state for c in ['d', 'h', 'w']):
            cleaned = state.replace("d", "").replace("h", "").replace("w", "")
            if cleaned.isdigit():
                return True
        return False

    # Parse OSPF results (indices 0-3)
    for i, router in enumerate(["R1", "R2", "R3", "R4"]):
        result = outputs[i]
        if isinstance(result, Exception):
            results["ospf"][router] = {"neighbors": 0, "status": "error", "error": str(result)}
            results["summary"]["failed"] += 1
            results["summary"]["tests"].append(f"OSPF {router}: ERROR")
        else:
            device, cmd, output = result
            if "Error:" in output:
                results["ospf"][router] = {"neighbors": 0, "status": "error", "error": output}
                results["summary"]["failed"] += 1
                results["summary"]["tests"].append(f"OSPF {router}: ERROR")
            else:
                neighbor_count = len([line for line in output.splitlines() if "FULL" in line])
                status = "healthy" if neighbor_count >= 2 else ("degraded" if neighbor_count >= 1 else "critical")
                results["ospf"][router] = {"neighbors": neighbor_count, "status": status}
                if status == "healthy":
                    results["summary"]["passed"] += 1
                    results["summary"]["tests"].append(f"OSPF {router}: {neighbor_count} neighbors")
                else:
                    results["summary"]["failed"] += 1
                    results["summary"]["tests"].append(f"OSPF {router}: only {neighbor_count} neighbors")

    # Parse R1 BGP results (index 4)
    r1_bgp = outputs[4]
    if isinstance(r1_bgp, Exception):
        results["bgp"]["ibgp"]["R1"] = {"status": "error", "error": str(r1_bgp)}
        results["summary"]["failed"] += 1
    else:
        device, cmd, output = r1_bgp
        if "Error:" in output:
            results["bgp"]["ibgp"]["R1"] = {"status": "error", "error": output}
            results["summary"]["failed"] += 1
        else:
            ibgp_peers = {}
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 9 and parts[0].count('.') == 3:
                    neighbor_ip = parts[0]
                    state = parts[8] if len(parts) > 8 else "unknown"
                    ip_to_router = {LOOPBACK_MAP.get(r, ""): r for r in ("R2", "R3", "R4") if r in LOOPBACK_MAP}
                    router_name = ip_to_router.get(neighbor_ip, neighbor_ip)
                    if is_bgp_established(state):
                        ibgp_peers[f"R1-{router_name}"] = "Established"
                    else:
                        ibgp_peers[f"R1-{router_name}"] = state
            results["bgp"]["ibgp"] = ibgp_peers
            established_count = sum(1 for v in ibgp_peers.values() if v == "Established")
            if established_count >= 3:
                results["summary"]["passed"] += 1
                results["summary"]["tests"].append(f"iBGP R1: {established_count}/3 peers established")
            else:
                results["summary"]["failed"] += 1
                results["summary"]["tests"].append(f"iBGP R1: only {established_count}/3 peers established")

    # Parse R3 BGP results (index 5)
    r3_bgp = outputs[5]
    if isinstance(r3_bgp, Exception):
        results["bgp"]["ebgp"]["R3-edge1"] = "error"
        results["summary"]["failed"] += 1
    else:
        device, cmd, output = r3_bgp
        if "Error:" in output:
            results["bgp"]["ebgp"]["R3-edge1"] = "error"
            results["summary"]["failed"] += 1
        else:
            ebgp_established = False
            for line in output.splitlines():
                if line.strip().startswith("172.20.20.") and "65100" in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        state = parts[8]
                        if is_bgp_established(state):
                            results["bgp"]["ebgp"]["R3-edge1"] = "Established"
                            ebgp_established = True
                        else:
                            results["bgp"]["ebgp"]["R3-edge1"] = state
            if ebgp_established:
                results["summary"]["passed"] += 1
                results["summary"]["tests"].append("eBGP R3-edge1: Established")
            else:
                if "R3-edge1" not in results["bgp"]["ebgp"]:
                    results["bgp"]["ebgp"]["R3-edge1"] = "not found"
                results["summary"]["failed"] += 1
                results["summary"]["tests"].append(f"eBGP R3-edge1: {results['bgp']['ebgp']['R3-edge1']}")

    # Parse DMVPN results (index 6)
    dmvpn_result = outputs[6]
    if isinstance(dmvpn_result, Exception):
        results["dmvpn"]["status"] = "error"
        results["summary"]["failed"] += 1
    else:
        device, cmd, output = dmvpn_result
        if "Error:" in output:
            results["dmvpn"]["status"] = "error"
            results["dmvpn"]["error"] = output
            results["summary"]["failed"] += 1
        else:
            spoke_map = {"172.16.0.2": "R2", "172.16.0.3": "R3", "172.16.0.4": "R4"}
            for tunnel_ip, spoke_name in spoke_map.items():
                if tunnel_ip in output:
                    for line in output.splitlines():
                        if tunnel_ip in line and "UP" in line:
                            results["dmvpn"]["spokes"][spoke_name] = "UP"
                            break
                    if spoke_name not in results["dmvpn"]["spokes"]:
                        results["dmvpn"]["spokes"][spoke_name] = "DOWN"
                else:
                    results["dmvpn"]["spokes"][spoke_name] = "not found"

            up_count = sum(1 for v in results["dmvpn"]["spokes"].values() if v == "UP")
            if up_count >= 3:
                results["dmvpn"]["status"] = "healthy"
                results["summary"]["passed"] += 1
                results["summary"]["tests"].append(f"DMVPN: {up_count}/3 spokes UP")
            else:
                results["dmvpn"]["status"] = "degraded"
                results["summary"]["failed"] += 1
                results["summary"]["tests"].append(f"DMVPN: only {up_count}/3 spokes UP")

    # Parse Ping results (indices 7-9)
    ping_targets = [(r, LOOPBACK_MAP[r]) for r in ("R2", "R3", "R4") if r in LOOPBACK_MAP]
    for i, (target_name, target_ip) in enumerate(ping_targets):
        ping_result = outputs[7 + i]
        if isinstance(ping_result, Exception):
            results["ping"][f"R1->{target_name}"] = "error"
            results["summary"]["failed"] += 1
            results["summary"]["tests"].append(f"Ping R1->{target_name}: ERROR")
        else:
            device, cmd, output = ping_result
            if "Error:" in output:
                results["ping"][f"R1->{target_name}"] = "error"
                results["summary"]["failed"] += 1
                results["summary"]["tests"].append(f"Ping R1->{target_name}: ERROR")
            else:
                success_match = re.search(r"Success rate is (\d+) percent", output)
                if success_match:
                    success_rate = int(success_match.group(1))
                    results["ping"][f"R1->{target_name}"] = f"{success_rate}%"
                    if success_rate == 100:
                        results["summary"]["passed"] += 1
                        results["summary"]["tests"].append(f"Ping R1->{target_name}: 100%")
                    else:
                        results["summary"]["failed"] += 1
                        results["summary"]["tests"].append(f"Ping R1->{target_name}: {success_rate}%")
                else:
                    results["ping"][f"R1->{target_name}"] = "unknown"
                    results["summary"]["failed"] += 1
                    results["summary"]["tests"].append(f"Ping R1->{target_name}: unknown")

    # Final summary
    elapsed = time.time() - start
    results["elapsed_seconds"] = round(elapsed, 2)
    total_tests = results["summary"]["passed"] + results["summary"]["failed"]
    if results["summary"]["failed"] == 0:
        results["summary"]["status"] = "ALL TESTS PASSED"
    elif results["summary"]["passed"] > results["summary"]["failed"]:
        results["summary"]["status"] = "PARTIAL SUCCESS"
    else:
        results["summary"]["status"] = "CRITICAL FAILURES"

    log_event("full_network_test", None,
              f"Passed: {results['summary']['passed']}/{total_tests}",
              "success" if results["summary"]["failed"] == 0 else "warning",
              "system")

    return json.dumps(results, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": backup_config, "name": "backup_config", "category": "config"},
    {"fn": compare_configs, "name": "compare_configs", "category": "config"},
    {"fn": list_backups, "name": "list_backups", "category": "config"},
    {"fn": rollback_config, "name": "rollback_config", "category": "config"},
    {"fn": export_documentation, "name": "export_documentation", "category": "config"},
    {"fn": full_network_test, "name": "full_network_test", "category": "config"},
]
