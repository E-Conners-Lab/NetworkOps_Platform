"""
Ansible Integration for NetworkOps

Provides playbook execution and inventory management via Ansible.
Integrates with existing device inventory (config/devices.py or NetBox).

Feature Flag: use_ansible (default: false)

Key Features:
- Execute playbooks from ansible/playbooks/
- Dynamic inventory generation from config/devices.py
- Structured results with per-host status
- Support for extra variables and host limits
- Dry-run (check mode) support

Usage:
    from core.ansible_manager import AnsibleManager, get_ansible

    ansible = get_ansible()
    result = ansible.run_playbook("health_check")

    # With host limit
    result = ansible.run_playbook("backup_configs", limit="R1,R2")

    # With extra variables
    result = ansible.run_playbook("deploy_changes", extra_vars={"commands": ["logging host 198.51.100.1"]})
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from core.feature_flags import is_enabled

logger = logging.getLogger(__name__)

# Project root for finding ansible directory
PROJECT_ROOT = Path(__file__).parent.parent
ANSIBLE_DIR = PROJECT_ROOT / "ansible"
PLAYBOOKS_DIR = ANSIBLE_DIR / "playbooks"
INVENTORY_FILE = ANSIBLE_DIR / "inventory" / "hosts.yml"


@dataclass
class PlaybookResult:
    """Result of a playbook execution"""
    playbook: str
    success: bool
    changed: int = 0
    failed: int = 0
    ok: int = 0
    skipped: int = 0
    unreachable: int = 0
    hosts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    elapsed_time: float = 0.0
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook": self.playbook,
            "success": self.success,
            "summary": {
                "ok": self.ok,
                "changed": self.changed,
                "failed": self.failed,
                "skipped": self.skipped,
                "unreachable": self.unreachable,
            },
            "hosts": self.hosts,
            "elapsed_time": round(self.elapsed_time, 2),
            "return_code": self.return_code,
        }

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    def failed_hosts(self) -> List[str]:
        """Get list of hosts that failed"""
        return [
            host for host, stats in self.hosts.items()
            if stats.get("failed", 0) > 0 or stats.get("unreachable", False)
        ]

    def successful_hosts(self) -> List[str]:
        """Get list of hosts that succeeded"""
        return [
            host for host, stats in self.hosts.items()
            if stats.get("failed", 0) == 0 and not stats.get("unreachable", False)
        ]


@dataclass
class PlaybookInfo:
    """Information about an available playbook"""
    name: str
    path: str
    description: str = ""
    hosts: str = "all"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "hosts": self.hosts,
            "tags": self.tags,
        }


class AnsibleManager:
    """
    Manages Ansible operations with NetworkOps inventory.

    Provides playbook execution using ansible-playbook CLI with
    structured result parsing.
    """

    def __init__(self, ansible_dir: Optional[Path] = None):
        """
        Initialize AnsibleManager.

        Args:
            ansible_dir: Path to ansible directory (default: project_root/ansible)
        """
        self.ansible_dir = ansible_dir or ANSIBLE_DIR
        self.playbooks_dir = self.ansible_dir / "playbooks"
        self.inventory_file = self.ansible_dir / "inventory" / "hosts.yml"
        self._ansible_available = None

    @property
    def ansible_available(self) -> bool:
        """Check if ansible-playbook command is available"""
        if self._ansible_available is None:
            try:
                result = subprocess.run(
                    ["ansible-playbook", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self._ansible_available = result.returncode == 0
                if self._ansible_available:
                    version_match = re.search(r"ansible.*?(\d+\.\d+\.\d+)", result.stdout)
                    if version_match:
                        logger.debug(f"Ansible version: {version_match.group(1)}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self._ansible_available = False
                logger.debug("ansible-playbook not found")
        return self._ansible_available

    def list_playbooks(self) -> List[PlaybookInfo]:
        """
        List available playbooks in the playbooks directory.

        Returns:
            List of PlaybookInfo objects
        """
        playbooks = []

        if not self.playbooks_dir.exists():
            return playbooks

        for playbook_file in self.playbooks_dir.glob("*.yml"):
            name = playbook_file.stem
            info = self._parse_playbook_info(playbook_file)
            playbooks.append(PlaybookInfo(
                name=name,
                path=str(playbook_file),
                description=info.get("description", ""),
                hosts=info.get("hosts", "all"),
                tags=info.get("tags", []),
            ))

        return sorted(playbooks, key=lambda p: p.name)

    def _parse_playbook_info(self, playbook_path: Path) -> Dict[str, Any]:
        """Parse playbook YAML to extract metadata"""
        import yaml

        try:
            with open(playbook_path) as f:
                content = yaml.safe_load(f)

            if isinstance(content, list) and len(content) > 0:
                first_play = content[0]
                return {
                    "description": first_play.get("name", ""),
                    "hosts": first_play.get("hosts", "all"),
                    "tags": first_play.get("tags", []),
                }
        except Exception as e:
            logger.debug(f"Failed to parse {playbook_path}: {e}")

        return {}

    def run_playbook(
        self,
        playbook: str,
        limit: Optional[str] = None,
        extra_vars: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        skip_tags: Optional[List[str]] = None,
        check_mode: bool = False,
        verbose: int = 0,
        timeout: int = 300,
    ) -> PlaybookResult:
        """
        Execute an Ansible playbook.

        Args:
            playbook: Playbook name (without .yml) or full path
            limit: Host pattern to limit execution (e.g., "R1,R2" or "cisco_routers")
            extra_vars: Dictionary of extra variables to pass
            tags: List of tags to run
            skip_tags: List of tags to skip
            check_mode: Run in check mode (dry-run)
            verbose: Verbosity level (0-4, maps to -v through -vvvv)
            timeout: Execution timeout in seconds

        Returns:
            PlaybookResult with execution details
        """
        if not is_enabled("use_ansible"):
            return PlaybookResult(
                playbook=playbook,
                success=False,
                stderr="Ansible integration is disabled. Set FF_USE_ANSIBLE=true to enable.",
                return_code=-1,
            )

        if not self.ansible_available:
            return PlaybookResult(
                playbook=playbook,
                success=False,
                stderr="ansible-playbook command not found. Install with: pip install ansible",
                return_code=-1,
            )

        # Resolve playbook path
        if os.path.isabs(playbook):
            playbook_path = Path(playbook)
        else:
            playbook_path = self.playbooks_dir / f"{playbook}.yml"
            if not playbook_path.exists():
                playbook_path = self.playbooks_dir / playbook

        if not playbook_path.exists():
            return PlaybookResult(
                playbook=playbook,
                success=False,
                stderr=f"Playbook not found: {playbook_path}",
                return_code=-1,
            )

        # Build command
        cmd = [
            "ansible-playbook",
            str(playbook_path),
            "-i", str(self.inventory_file),
        ]

        # Add limit
        if limit:
            cmd.extend(["--limit", limit])

        # Add extra vars
        if extra_vars:
            extra_vars_json = json.dumps(extra_vars)
            cmd.extend(["--extra-vars", extra_vars_json])

        # Add tags
        if tags:
            cmd.extend(["--tags", ",".join(tags)])

        if skip_tags:
            cmd.extend(["--skip-tags", ",".join(skip_tags)])

        # Check mode
        if check_mode:
            cmd.append("--check")

        # Verbosity
        if verbose > 0:
            cmd.append("-" + "v" * min(verbose, 4))

        # Always use JSON callback for structured output
        env = os.environ.copy()
        env["ANSIBLE_STDOUT_CALLBACK"] = "json"
        env["ANSIBLE_LOAD_CALLBACK_PLUGINS"] = "1"
        env["ANSIBLE_CONFIG"] = str(self.ansible_dir / "ansible.cfg")

        # Execute
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.ansible_dir),
                env=env,
            )
            elapsed = time.time() - start_time

            # Parse results
            return self._parse_playbook_output(
                playbook=playbook,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                elapsed_time=elapsed,
            )

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return PlaybookResult(
                playbook=playbook,
                success=False,
                stderr=f"Playbook execution timed out after {timeout} seconds",
                return_code=-1,
                elapsed_time=elapsed,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return PlaybookResult(
                playbook=playbook,
                success=False,
                stderr=str(e),
                return_code=-1,
                elapsed_time=elapsed,
            )

    def _parse_playbook_output(
        self,
        playbook: str,
        stdout: str,
        stderr: str,
        return_code: int,
        elapsed_time: float,
    ) -> PlaybookResult:
        """Parse ansible-playbook JSON output"""
        hosts = {}
        ok = changed = failed = skipped = unreachable = 0

        try:
            # Try to parse JSON output
            data = json.loads(stdout)

            # Get stats from JSON output
            stats = data.get("stats", {})
            for host, host_stats in stats.items():
                hosts[host] = host_stats
                ok += host_stats.get("ok", 0)
                changed += host_stats.get("changed", 0)
                failed += host_stats.get("failures", 0)
                skipped += host_stats.get("skipped", 0)
                unreachable += 1 if host_stats.get("unreachable", 0) > 0 else 0

        except json.JSONDecodeError:
            # Fall back to parsing text output
            hosts, stats = self._parse_text_output(stdout)
            ok = stats.get("ok", 0)
            changed = stats.get("changed", 0)
            failed = stats.get("failed", 0)
            skipped = stats.get("skipped", 0)
            unreachable = stats.get("unreachable", 0)

        success = return_code == 0 and failed == 0 and unreachable == 0

        return PlaybookResult(
            playbook=playbook,
            success=success,
            ok=ok,
            changed=changed,
            failed=failed,
            skipped=skipped,
            unreachable=unreachable,
            hosts=hosts,
            elapsed_time=elapsed_time,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
        )

    def _parse_text_output(self, stdout: str) -> tuple:
        """Parse text output when JSON parsing fails"""
        hosts = {}
        stats = {"ok": 0, "changed": 0, "failed": 0, "skipped": 0, "unreachable": 0}

        # Look for PLAY RECAP section
        recap_match = re.search(r"PLAY RECAP \*+\s*\n(.*)", stdout, re.DOTALL)
        if recap_match:
            recap_text = recap_match.group(1)

            # Parse each host line
            for line in recap_text.strip().split("\n"):
                if not line.strip():
                    continue

                # Format: "hostname : ok=X changed=Y unreachable=Z failed=W skipped=S"
                host_match = re.match(
                    r"(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)",
                    line,
                )
                if host_match:
                    host = host_match.group(1)
                    host_ok = int(host_match.group(2))
                    host_changed = int(host_match.group(3))
                    host_unreachable = int(host_match.group(4))
                    host_failed = int(host_match.group(5))

                    hosts[host] = {
                        "ok": host_ok,
                        "changed": host_changed,
                        "unreachable": host_unreachable,
                        "failures": host_failed,
                    }

                    stats["ok"] += host_ok
                    stats["changed"] += host_changed
                    stats["failed"] += host_failed
                    stats["unreachable"] += 1 if host_unreachable > 0 else 0

        return hosts, stats

    def run_adhoc(
        self,
        hosts: str,
        module: str,
        args: Optional[str] = None,
        become: bool = False,
        timeout: int = 60,
    ) -> PlaybookResult:
        """
        Run an ad-hoc Ansible command.

        Args:
            hosts: Host pattern (e.g., "R1", "cisco_routers", "all")
            module: Ansible module name (e.g., "cisco.ios.ios_command")
            args: Module arguments (e.g., "commands='show version'")
            become: Use privilege escalation
            timeout: Execution timeout in seconds

        Returns:
            PlaybookResult with execution details
        """
        if not is_enabled("use_ansible"):
            return PlaybookResult(
                playbook=f"adhoc:{module}",
                success=False,
                stderr="Ansible integration is disabled. Set FF_USE_ANSIBLE=true to enable.",
                return_code=-1,
            )

        if not self.ansible_available:
            return PlaybookResult(
                playbook=f"adhoc:{module}",
                success=False,
                stderr="ansible command not found",
                return_code=-1,
            )

        # Build command
        cmd = [
            "ansible",
            hosts,
            "-i", str(self.inventory_file),
            "-m", module,
        ]

        if args:
            cmd.extend(["-a", args])

        if become:
            cmd.append("--become")

        # Environment
        env = os.environ.copy()
        env["ANSIBLE_CONFIG"] = str(self.ansible_dir / "ansible.cfg")

        # Execute
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.ansible_dir),
                env=env,
            )
            elapsed = time.time() - start_time

            return PlaybookResult(
                playbook=f"adhoc:{module}",
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                elapsed_time=elapsed,
            )

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return PlaybookResult(
                playbook=f"adhoc:{module}",
                success=False,
                stderr=f"Command timed out after {timeout} seconds",
                return_code=-1,
                elapsed_time=elapsed,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return PlaybookResult(
                playbook=f"adhoc:{module}",
                success=False,
                stderr=str(e),
                return_code=-1,
                elapsed_time=elapsed,
            )

    def get_inventory(self, host: Optional[str] = None) -> Dict[str, Any]:
        """
        Get inventory information.

        Args:
            host: Specific host to get info for (optional)

        Returns:
            Dict with inventory data
        """
        cmd = ["ansible-inventory", "-i", str(self.inventory_file), "--list"]

        if host:
            cmd = ["ansible-inventory", "-i", str(self.inventory_file), "--host", host]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}

        except Exception as e:
            return {"error": str(e)}

    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of Ansible configuration and available playbooks.

        Returns:
            Dict with Ansible summary
        """
        playbooks = self.list_playbooks()
        inventory = self.get_inventory()

        # Count hosts by group
        groups = {}
        if "_meta" in inventory and "hostvars" in inventory["_meta"]:
            total_hosts = len(inventory["_meta"]["hostvars"])
        else:
            total_hosts = 0

        for group_name, group_data in inventory.items():
            if group_name not in ["_meta", "all"]:
                if isinstance(group_data, dict) and "hosts" in group_data:
                    groups[group_name] = len(group_data["hosts"])

        return {
            "ansible_available": self.ansible_available,
            "ansible_enabled": is_enabled("use_ansible"),
            "ansible_dir": str(self.ansible_dir),
            "inventory_file": str(self.inventory_file),
            "playbooks": [p.to_dict() for p in playbooks],
            "playbook_count": len(playbooks),
            "inventory": {
                "total_hosts": total_hosts,
                "groups": groups,
            },
        }

    def generate_inventory(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Generate inventory YAML from config/devices.py.

        Args:
            output_path: Path to write inventory (optional)

        Returns:
            Dict with generated inventory
        """
        import yaml
        from config.devices import DEVICES, USERNAME, PASSWORD

        # Build inventory structure
        inventory = {
            "all": {
                "children": {
                    "cisco_routers": {"hosts": {}},
                    "cisco_switches": {"hosts": {}},
                    "linux_hosts": {"hosts": {}},
                    "containerlab": {"hosts": {}, "vars": {"containerlab_vm": "containerlab"}},
                }
            }
        }

        for name, device in DEVICES.items():
            device_type = device.get("device_type", "")
            host = device.get("host", "")

            host_entry = {
                "ansible_host": host,
            }

            if device_type == "cisco_xe":
                host_entry["ansible_network_os"] = "cisco.ios.ios"
                host_entry["ansible_connection"] = "ansible.netcommon.network_cli"
                if "router" in name.lower() or name.startswith("R"):
                    inventory["all"]["children"]["cisco_routers"]["hosts"][name] = host_entry
                else:
                    inventory["all"]["children"]["cisco_switches"]["hosts"][name] = host_entry

            elif device_type == "linux":
                host_entry["ansible_connection"] = "ssh"
                inventory["all"]["children"]["linux_hosts"]["hosts"][name] = host_entry

            elif device_type.startswith("containerlab_"):
                host_entry["ansible_connection"] = "local"
                host_entry["containerlab_type"] = device_type.replace("containerlab_", "")
                host_entry["container_name"] = f"clab-datacenter-{name}"
                inventory["all"]["children"]["containerlab"]["hosts"][name] = host_entry

        if output_path:
            with open(output_path, "w") as f:
                yaml.dump(inventory, f, default_flow_style=False)

        return inventory


# Singleton instance
_ansible_manager = None


def get_ansible(ansible_dir: Optional[Path] = None) -> AnsibleManager:
    """Get singleton AnsibleManager instance"""
    global _ansible_manager
    if _ansible_manager is None:
        _ansible_manager = AnsibleManager(ansible_dir=ansible_dir)
    return _ansible_manager


def run_playbook(
    playbook: str,
    limit: Optional[str] = None,
    extra_vars: Optional[Dict[str, Any]] = None,
    check_mode: bool = False,
) -> PlaybookResult:
    """
    Convenience function to run a playbook.

    Args:
        playbook: Playbook name or path
        limit: Host limit pattern
        extra_vars: Extra variables
        check_mode: Dry-run mode

    Returns:
        PlaybookResult
    """
    manager = get_ansible()
    return manager.run_playbook(
        playbook=playbook,
        limit=limit,
        extra_vars=extra_vars,
        check_mode=check_mode,
    )
