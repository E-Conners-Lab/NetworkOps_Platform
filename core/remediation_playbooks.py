"""
Automated Remediation Playbooks for NetworkOps.

Provides predefined and customizable playbooks for automated remediation
of common network issues with pre/post validation and rollback support.

Features:
- Built-in playbooks for common issues
- Step-by-step execution with validation
- Automatic rollback on failure
- Execution history and audit logging
- Dry-run mode for testing

Usage:
    from core.remediation_playbooks import PlaybookExecutor

    executor = PlaybookExecutor()

    # List available playbooks
    playbooks = executor.list_playbooks()

    # Execute a playbook
    result = await executor.execute("interface_bounce", device="R1", interface="Gi1")
"""

import asyncio
import json
import logging
import sqlite3
from dataclasses import dataclass, field, asdict
from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, Any
from uuid import uuid4

from core.db import DatabaseManager

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================


# =============================================================================
# Data Models
# =============================================================================

class PlaybookStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class StepType(str, Enum):
    COMMAND = "command"  # Execute a show command
    CONFIG = "config"  # Apply configuration
    VALIDATE = "validate"  # Validation check
    WAIT = "wait"  # Wait for a duration


@dataclass
class PlaybookStep:
    """A single step in a playbook."""
    name: str
    step_type: StepType
    commands: list[str] = field(default_factory=list)
    config: list[str] = field(default_factory=list)
    wait_seconds: int = 0
    validation_pattern: str = None  # Regex to match in output
    validation_must_match: bool = True  # True = pattern must match, False = must not match
    rollback_config: list[str] = field(default_factory=list)
    continue_on_fail: bool = False

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "step_type": self.step_type.value,
        }


@dataclass
class Playbook:
    """A remediation playbook definition."""
    id: str
    name: str
    description: str
    category: str
    severity: str  # What severity of issue this remediates
    parameters: list[str]  # Required parameters (e.g., ["device", "interface"])
    steps: list[PlaybookStep]
    estimated_duration: int  # Seconds
    requires_approval: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "parameters": self.parameters,
            "steps": [s.to_dict() for s in self.steps],
            "estimated_duration": self.estimated_duration,
            "requires_approval": self.requires_approval,
            "tags": self.tags,
        }


@dataclass
class StepResult:
    """Result of executing a playbook step."""
    step_name: str
    status: PlaybookStatus
    started_at: str
    completed_at: str
    output: str
    error: str = None

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "status": self.status.value,
        }


@dataclass
class ExecutionResult:
    """Result of executing a playbook."""
    execution_id: str
    playbook_id: str
    device: str
    status: PlaybookStatus
    started_at: str
    completed_at: str
    parameters: dict
    step_results: list[StepResult]
    rollback_performed: bool = False
    dry_run: bool = False

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "status": self.status.value,
            "step_results": [s.to_dict() for s in self.step_results],
        }


# =============================================================================
# Built-in Playbooks
# =============================================================================

BUILT_IN_PLAYBOOKS = [
    Playbook(
        id="interface_bounce",
        name="Interface Bounce",
        description="Bounce an interface by shutting it down and bringing it back up",
        category="Interface",
        severity="medium",
        parameters=["device", "interface"],
        estimated_duration=30,
        requires_approval=False,
        tags=["interface", "connectivity"],
        steps=[
            PlaybookStep(
                name="Check current state",
                step_type=StepType.COMMAND,
                commands=["show interface {interface} | include line protocol"],
            ),
            PlaybookStep(
                name="Shutdown interface",
                step_type=StepType.CONFIG,
                config=["interface {interface}", "shutdown"],
                rollback_config=["interface {interface}", "no shutdown"],
            ),
            PlaybookStep(
                name="Wait for shutdown",
                step_type=StepType.WAIT,
                wait_seconds=5,
            ),
            PlaybookStep(
                name="Bring interface up",
                step_type=StepType.CONFIG,
                config=["interface {interface}", "no shutdown"],
            ),
            PlaybookStep(
                name="Wait for convergence",
                step_type=StepType.WAIT,
                wait_seconds=10,
            ),
            PlaybookStep(
                name="Verify interface up",
                step_type=StepType.VALIDATE,
                commands=["show interface {interface} | include line protocol"],
                validation_pattern=r"line protocol is up",
                validation_must_match=True,
            ),
        ],
    ),
    Playbook(
        id="clear_interface_counters",
        name="Clear Interface Counters",
        description="Clear error and traffic counters on an interface",
        category="Interface",
        severity="low",
        parameters=["device", "interface"],
        estimated_duration=10,
        requires_approval=False,
        tags=["interface", "counters"],
        steps=[
            PlaybookStep(
                name="Capture current counters",
                step_type=StepType.COMMAND,
                commands=["show interface {interface} | include errors"],
            ),
            PlaybookStep(
                name="Clear counters",
                step_type=StepType.COMMAND,
                commands=["clear counters {interface}"],
            ),
            PlaybookStep(
                name="Wait for clear",
                step_type=StepType.WAIT,
                wait_seconds=2,
            ),
            PlaybookStep(
                name="Verify counters cleared",
                step_type=StepType.COMMAND,
                commands=["show interface {interface} | include errors"],
            ),
        ],
    ),
    Playbook(
        id="ospf_reset_neighbor",
        name="Reset OSPF Neighbor",
        description="Clear OSPF neighbor adjacency to force re-establishment",
        category="Routing",
        severity="medium",
        parameters=["device", "neighbor_ip"],
        estimated_duration=60,
        requires_approval=True,
        tags=["ospf", "routing", "neighbor"],
        steps=[
            PlaybookStep(
                name="Check current OSPF state",
                step_type=StepType.COMMAND,
                commands=["show ip ospf neighbor {neighbor_ip}"],
            ),
            PlaybookStep(
                name="Clear OSPF neighbor",
                step_type=StepType.COMMAND,
                commands=["clear ip ospf process"],  # IOS-XE requires confirm which we handle
            ),
            PlaybookStep(
                name="Wait for adjacency",
                step_type=StepType.WAIT,
                wait_seconds=30,
            ),
            PlaybookStep(
                name="Verify neighbor up",
                step_type=StepType.VALIDATE,
                commands=["show ip ospf neighbor {neighbor_ip}"],
                validation_pattern=r"FULL",
                validation_must_match=True,
            ),
        ],
    ),
    Playbook(
        id="bgp_reset_neighbor",
        name="Reset BGP Neighbor",
        description="Soft reset a BGP neighbor session",
        category="Routing",
        severity="medium",
        parameters=["device", "neighbor_ip"],
        estimated_duration=45,
        requires_approval=True,
        tags=["bgp", "routing", "neighbor"],
        steps=[
            PlaybookStep(
                name="Check current BGP state",
                step_type=StepType.COMMAND,
                commands=["show ip bgp neighbor {neighbor_ip} | include BGP state"],
            ),
            PlaybookStep(
                name="Soft reset BGP neighbor",
                step_type=StepType.COMMAND,
                commands=["clear ip bgp {neighbor_ip} soft"],
            ),
            PlaybookStep(
                name="Wait for session",
                step_type=StepType.WAIT,
                wait_seconds=15,
            ),
            PlaybookStep(
                name="Verify session established",
                step_type=StepType.VALIDATE,
                commands=["show ip bgp neighbor {neighbor_ip} | include BGP state"],
                validation_pattern=r"Established",
                validation_must_match=True,
            ),
        ],
    ),
    Playbook(
        id="fix_mtu_mismatch",
        name="Fix MTU Mismatch",
        description="Set MTU on interface to resolve OSPF or connectivity issues",
        category="Interface",
        severity="medium",
        parameters=["device", "interface", "mtu"],
        estimated_duration=30,
        requires_approval=True,
        tags=["interface", "mtu", "ospf"],
        steps=[
            PlaybookStep(
                name="Check current MTU",
                step_type=StepType.COMMAND,
                commands=["show interface {interface} | include MTU"],
            ),
            PlaybookStep(
                name="Set new MTU",
                step_type=StepType.CONFIG,
                config=["interface {interface}", "mtu {mtu}"],
                rollback_config=["interface {interface}", "no mtu"],
            ),
            PlaybookStep(
                name="Wait for change",
                step_type=StepType.WAIT,
                wait_seconds=5,
            ),
            PlaybookStep(
                name="Verify MTU set",
                step_type=StepType.VALIDATE,
                commands=["show interface {interface} | include MTU"],
                validation_pattern=r"MTU {mtu}",
                validation_must_match=True,
            ),
        ],
    ),
    Playbook(
        id="clear_arp_cache",
        name="Clear ARP Cache",
        description="Clear the ARP cache to resolve stale ARP entries",
        category="Layer2",
        severity="low",
        parameters=["device"],
        estimated_duration=15,
        requires_approval=False,
        tags=["arp", "layer2"],
        steps=[
            PlaybookStep(
                name="Check current ARP entries",
                step_type=StepType.COMMAND,
                commands=["show ip arp | count"],
            ),
            PlaybookStep(
                name="Clear ARP cache",
                step_type=StepType.COMMAND,
                commands=["clear ip arp"],
            ),
            PlaybookStep(
                name="Wait for ARP rebuild",
                step_type=StepType.WAIT,
                wait_seconds=5,
            ),
            PlaybookStep(
                name="Check new ARP state",
                step_type=StepType.COMMAND,
                commands=["show ip arp | count"],
            ),
        ],
    ),
    Playbook(
        id="recover_cpu_high",
        name="Recover from High CPU",
        description="Attempt to recover from high CPU by clearing processes and caches",
        category="System",
        severity="high",
        parameters=["device"],
        estimated_duration=60,
        requires_approval=True,
        tags=["cpu", "performance"],
        steps=[
            PlaybookStep(
                name="Check current CPU",
                step_type=StepType.COMMAND,
                commands=["show processes cpu sorted | head 10"],
            ),
            PlaybookStep(
                name="Check process history",
                step_type=StepType.COMMAND,
                commands=["show processes cpu history"],
            ),
            PlaybookStep(
                name="Clear IP routing cache",
                step_type=StepType.COMMAND,
                commands=["clear ip cache"],
            ),
            PlaybookStep(
                name="Wait for stabilization",
                step_type=StepType.WAIT,
                wait_seconds=30,
            ),
            PlaybookStep(
                name="Verify CPU reduced",
                step_type=StepType.VALIDATE,
                commands=["show processes cpu | include CPU utilization"],
                validation_pattern=r"one minute: [0-6][0-9]%",  # Below 70%
                validation_must_match=True,
                continue_on_fail=True,  # Don't fail playbook if CPU still high
            ),
        ],
    ),
    Playbook(
        id="nhrp_clear_cache",
        name="Clear NHRP Cache",
        description="Clear NHRP cache to resolve DMVPN tunnel issues",
        category="VPN",
        severity="medium",
        parameters=["device"],
        estimated_duration=45,
        requires_approval=False,
        tags=["dmvpn", "nhrp", "vpn"],
        steps=[
            PlaybookStep(
                name="Check current NHRP cache",
                step_type=StepType.COMMAND,
                commands=["show ip nhrp"],
            ),
            PlaybookStep(
                name="Clear NHRP cache",
                step_type=StepType.COMMAND,
                commands=["clear ip nhrp"],
            ),
            PlaybookStep(
                name="Wait for tunnel rebuild",
                step_type=StepType.WAIT,
                wait_seconds=20,
            ),
            PlaybookStep(
                name="Verify NHRP entries",
                step_type=StepType.COMMAND,
                commands=["show ip nhrp"],
            ),
        ],
    ),
    Playbook(
        id="remove_acl",
        name="Remove Interface ACL",
        description="Remove an ACL from an interface and delete its definition. "
                    "Use for rogue/misconfigured ACLs blocking routing protocols.",
        category="Interface",
        severity="high",
        parameters=["device", "interface", "acl_name"],
        estimated_duration=60,
        requires_approval=True,
        tags=["acl", "security", "interface", "ospf"],
        steps=[
            PlaybookStep(
                name="Show current ACL rules",
                step_type=StepType.COMMAND,
                commands=["show ip access-lists {acl_name}"],
            ),
            PlaybookStep(
                name="Remove ACL from interface",
                step_type=StepType.CONFIG,
                config=["interface {interface}", "no ip access-group {acl_name} in"],
                rollback_config=["interface {interface}", "ip access-group {acl_name} in"],
            ),
            PlaybookStep(
                name="Delete ACL definition",
                step_type=StepType.CONFIG,
                config=["no ip access-list extended {acl_name}"],
            ),
            PlaybookStep(
                name="Wait for OSPF reconvergence",
                step_type=StepType.WAIT,
                wait_seconds=45,
            ),
            PlaybookStep(
                name="Verify OSPF neighbor recovered",
                step_type=StepType.VALIDATE,
                commands=["show ip ospf neighbor"],
                validation_pattern=r"FULL",
                validation_must_match=True,
            ),
        ],
    ),
]


# =============================================================================
# Playbook Executor
# =============================================================================

class PlaybookExecutor:
    """
    Executes remediation playbooks with validation and rollback.
    """

    def __init__(self, db_path: Path = None):
        self._dm = DatabaseManager.get_instance()
        self._playbooks = {p.id: p for p in BUILT_IN_PLAYBOOKS}

    def list_playbooks(self, category: str = None, tag: str = None) -> list[dict]:
        """List available playbooks with optional filtering."""
        playbooks = list(self._playbooks.values())

        if category:
            playbooks = [p for p in playbooks if p.category.lower() == category.lower()]

        if tag:
            playbooks = [p for p in playbooks if tag.lower() in [t.lower() for t in p.tags]]

        return [p.to_dict() for p in playbooks]

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        return self._playbooks.get(playbook_id)

    async def execute(
        self,
        playbook_id: str,
        dry_run: bool = False,
        **params,
    ) -> ExecutionResult:
        """
        Execute a playbook.

        Args:
            playbook_id: ID of the playbook to execute
            dry_run: If True, simulate execution without making changes
            **params: Parameters required by the playbook (device, interface, etc.)

        Returns:
            ExecutionResult with step-by-step outcomes
        """
        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        # Validate required parameters
        for param in playbook.parameters:
            if param not in params:
                raise ValueError(f"Missing required parameter: {param}")

        device = params.get("device")
        execution_id = str(uuid4())[:8]
        started_at = isonow()

        result = ExecutionResult(
            execution_id=execution_id,
            playbook_id=playbook_id,
            device=device,
            status=PlaybookStatus.RUNNING,
            started_at=started_at,
            completed_at=None,
            parameters=params,
            step_results=[],
            rollback_performed=False,
            dry_run=dry_run,
        )

        rollback_steps = []
        failed_step = None

        try:
            for step in playbook.steps:
                step_result = await self._execute_step(step, device, params, dry_run)
                result.step_results.append(step_result)

                # Track rollback configs
                if step.rollback_config:
                    rollback_steps.append(step)

                if step_result.status == PlaybookStatus.FAILED:
                    if not step.continue_on_fail:
                        failed_step = step
                        break

            # Determine overall status
            if failed_step:
                result.status = PlaybookStatus.FAILED

                # Perform rollback if not dry run
                if not dry_run and rollback_steps:
                    await self._perform_rollback(device, rollback_steps, params)
                    result.rollback_performed = True
                    result.status = PlaybookStatus.ROLLED_BACK
            else:
                result.status = PlaybookStatus.SUCCESS

        except Exception as e:
            logger.error(f"Playbook execution error: {e}")
            result.status = PlaybookStatus.FAILED
            result.step_results.append(StepResult(
                step_name="Execution Error",
                status=PlaybookStatus.FAILED,
                started_at=isonow(),
                completed_at=isonow(),
                output="",
                error=str(e),
            ))

        result.completed_at = isonow()
        self._save_execution(result)

        return result

    async def _execute_step(
        self,
        step: PlaybookStep,
        device: str,
        params: dict,
        dry_run: bool,
    ) -> StepResult:
        """Execute a single playbook step."""
        started_at = isonow()
        output = ""
        error = None
        status = PlaybookStatus.SUCCESS

        try:
            if step.step_type == StepType.WAIT:
                if dry_run:
                    output = f"[DRY RUN] Would wait {step.wait_seconds} seconds"
                else:
                    await asyncio.sleep(step.wait_seconds)
                    output = f"Waited {step.wait_seconds} seconds"

            elif step.step_type == StepType.COMMAND:
                commands = [self._substitute_params(cmd, params) for cmd in step.commands]
                if dry_run:
                    output = f"[DRY RUN] Would execute: {commands}"
                else:
                    output = await self._run_commands(device, commands)

            elif step.step_type == StepType.CONFIG:
                config = [self._substitute_params(line, params) for line in step.config]
                if dry_run:
                    output = f"[DRY RUN] Would configure: {config}"
                else:
                    output = await self._apply_config(device, config)

            elif step.step_type == StepType.VALIDATE:
                commands = [self._substitute_params(cmd, params) for cmd in step.commands]
                if dry_run:
                    output = f"[DRY RUN] Would validate: {commands}"
                else:
                    output = await self._run_commands(device, commands)

                    # Check validation pattern
                    import re
                    pattern = self._substitute_params(step.validation_pattern, params)
                    match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)

                    if step.validation_must_match and not match:
                        status = PlaybookStatus.FAILED
                        error = f"Validation failed: pattern '{pattern}' not found"
                    elif not step.validation_must_match and match:
                        status = PlaybookStatus.FAILED
                        error = f"Validation failed: pattern '{pattern}' should not match"

        except Exception as e:
            status = PlaybookStatus.FAILED
            error = str(e)
            logger.error(f"Step '{step.name}' failed: {e}")

        return StepResult(
            step_name=step.name,
            status=status,
            started_at=started_at,
            completed_at=isonow(),
            output=output,
            error=error,
        )

    def _substitute_params(self, template: str, params: dict) -> str:
        """Substitute parameters in a template string."""
        result = template
        for key, value in params.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

    async def _run_commands(self, device: str, commands: list[str]) -> str:
        """Run commands on a device."""
        from core.scrapli_manager import get_ios_xe_connection

        outputs = []
        async with get_ios_xe_connection(device) as conn:
            for cmd in commands:
                resp = await conn.send_command(cmd)
                outputs.append(f">>> {cmd}\n{resp.result}")

        return "\n".join(outputs)

    async def _apply_config(self, device: str, config: list[str]) -> str:
        """Apply configuration to a device."""
        from core.scrapli_manager import get_ios_xe_connection

        async with get_ios_xe_connection(device) as conn:
            resp = await conn.send_configs(config)
            return resp.result if hasattr(resp, "result") else str(resp)

    async def _perform_rollback(
        self,
        device: str,
        steps: list[PlaybookStep],
        params: dict,
    ):
        """Perform rollback of all steps that had rollback configs."""
        logger.info(f"Performing rollback on {device}")

        # Rollback in reverse order
        for step in reversed(steps):
            if step.rollback_config:
                config = [self._substitute_params(line, params) for line in step.rollback_config]
                try:
                    await self._apply_config(device, config)
                    logger.info(f"Rolled back step: {step.name}")
                except Exception as e:
                    logger.error(f"Rollback failed for step {step.name}: {e}")

    def _save_execution(self, result: ExecutionResult):
        """Save execution result to database."""
        with self._dm.connect() as conn:
            conn.execute("""
                INSERT INTO executions
                (execution_id, playbook_id, device, status, started_at, completed_at,
                 parameters, step_results, rollback_performed, dry_run)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.execution_id,
                result.playbook_id,
                result.device,
                result.status.value,
                result.started_at,
                result.completed_at,
                json.dumps(result.parameters),
                json.dumps([s.to_dict() for s in result.step_results]),
                result.rollback_performed,
                result.dry_run,
            ))

    def get_execution_history(
        self,
        device: str = None,
        playbook_id: str = None,
        status: str = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get execution history with optional filters."""
        query = "SELECT * FROM executions WHERE 1=1"
        params = []

        if device:
            query += " AND device = ?"
            params.append(device)

        if playbook_id:
            query += " AND playbook_id = ?"
            params.append(playbook_id)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._dm.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

            results = []
            for row in rows:
                results.append({
                    "execution_id": row["execution_id"],
                    "playbook_id": row["playbook_id"],
                    "device": row["device"],
                    "status": row["status"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "parameters": json.loads(row["parameters"]),
                    "step_count": len(json.loads(row["step_results"])),
                    "rollback_performed": bool(row["rollback_performed"]),
                    "dry_run": bool(row["dry_run"]),
                })

            return results

    def get_execution(self, execution_id: str) -> Optional[dict]:
        """Get full details of a specific execution."""
        with self._dm.connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM executions WHERE execution_id = ?
            """, (execution_id,)).fetchone()

            if not row:
                return None

            return {
                "execution_id": row["execution_id"],
                "playbook_id": row["playbook_id"],
                "device": row["device"],
                "status": row["status"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "parameters": json.loads(row["parameters"]),
                "step_results": json.loads(row["step_results"]),
                "rollback_performed": bool(row["rollback_performed"]),
                "dry_run": bool(row["dry_run"]),
            }

    def add_custom_playbook(self, playbook: Playbook):
        """Add a custom playbook."""
        self._playbooks[playbook.id] = playbook


# =============================================================================
# Global Instance
# =============================================================================

_executor: Optional[PlaybookExecutor] = None


def get_playbook_executor() -> PlaybookExecutor:
    """Get the global playbook executor instance."""
    global _executor
    if _executor is None:
        _executor = PlaybookExecutor()
    return _executor
