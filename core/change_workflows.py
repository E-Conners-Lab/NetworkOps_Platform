"""
Automated Change Workflows for NetworkOps.

Provides structured change management with pre/post validation,
automatic rollback, and approval workflows.

Features:
- Change request lifecycle management
- Pre-change state capture (config, routes, interfaces)
- Post-change validation with configurable checks
- Automatic rollback on validation failure
- Approval workflow integration
- Full audit trail with timestamps

Usage:
    from core.change_workflows import ChangeManager, ChangeRequest

    manager = ChangeManager()

    # Create a change request
    change = await manager.create_change(
        device="R1",
        description="Add new loopback interface",
        commands=["interface Loopback99", "ip address 99.99.99.99 255.255.255.255"],
        validation_checks=["ping 99.99.99.99"]
    )

    # Execute with pre/post validation
    result = await manager.execute_change(change.id)

    # Rollback if needed
    await manager.rollback_change(change.id)
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field, asdict
from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional, Any

from core.db import DatabaseManager

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================


# =============================================================================
# Data Models
# =============================================================================

class ChangeStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class ChangeType(str, Enum):
    CONFIG = "config"  # Configuration commands
    INTERFACE = "interface"  # Interface changes
    ROUTING = "routing"  # Routing changes
    ACL = "acl"  # Access list changes
    MAINTENANCE = "maintenance"  # Maintenance window
    EMERGENCY = "emergency"  # Emergency change


class ValidationResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class PreChangeState:
    """Captured state before change."""
    device: str
    captured_at: str
    running_config: str
    interfaces: list[dict] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    neighbors: list[dict] = field(default_factory=list)
    custom_checks: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PostChangeValidation:
    """Validation results after change."""
    device: str
    validated_at: str
    overall_result: ValidationResult
    checks: list[dict] = field(default_factory=list)  # {name, result, expected, actual}
    config_diff: list[str] = field(default_factory=list)
    route_changes: list[dict] = field(default_factory=list)
    interface_changes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "validated_at": self.validated_at,
            "overall_result": self.overall_result.value,
            "checks": self.checks,
            "config_diff": self.config_diff,
            "route_changes": self.route_changes,
            "interface_changes": self.interface_changes,
        }


@dataclass
class ChangeRequest:
    """A change request with full lifecycle tracking."""
    id: str
    device: str
    description: str
    change_type: ChangeType
    status: ChangeStatus
    commands: list[str]
    validation_checks: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    pre_state: Optional[PreChangeState] = None
    post_validation: Optional[PostChangeValidation] = None
    created_at: str = ""
    created_by: str = "system"
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    execution_output: list[str] = field(default_factory=list)
    require_approval: bool = True
    auto_rollback: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device": self.device,
            "description": self.description,
            "change_type": self.change_type.value,
            "status": self.status.value,
            "commands": self.commands,
            "validation_checks": self.validation_checks,
            "rollback_commands": self.rollback_commands,
            "pre_state": self.pre_state.to_dict() if self.pre_state else None,
            "post_validation": self.post_validation.to_dict() if self.post_validation else None,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "executed_at": self.executed_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "execution_output": self.execution_output,
            "require_approval": self.require_approval,
            "auto_rollback": self.auto_rollback,
        }


# =============================================================================
# State Capture
# =============================================================================

class StateCapture:
    """Capture device state for pre/post validation."""

    @classmethod
    async def capture(cls, device_name: str, custom_commands: list[str] = None) -> PreChangeState:
        """
        Capture full device state.

        Args:
            device_name: Device to capture
            custom_commands: Additional commands to run

        Returns:
            PreChangeState with config, routes, interfaces
        """
        from config.devices import DEVICES
        from core.scrapli_manager import get_ios_xe_connection

        if device_name not in DEVICES:
            raise ValueError(f"Device '{device_name}' not found")

        state = PreChangeState(
            device=device_name,
            captured_at=isonow(),
            running_config="",
        )

        try:
            async with get_ios_xe_connection(device_name) as conn:
                # Get running config
                config_resp = await conn.send_command("show running-config")
                state.running_config = config_resp.result

                # Get interface status
                intf_resp = await conn.send_command("show ip interface brief")
                state.interfaces = cls._parse_interfaces(intf_resp.result)

                # Get routing table
                route_resp = await conn.send_command("show ip route")
                state.routes = cls._parse_routes(route_resp.result)

                # Get CDP/LLDP neighbors
                try:
                    neighbor_resp = await conn.send_command("show cdp neighbors")
                    state.neighbors = cls._parse_neighbors(neighbor_resp.result)
                except Exception:
                    state.neighbors = []

                # Run custom commands
                if custom_commands:
                    for cmd in custom_commands:
                        try:
                            resp = await conn.send_command(cmd)
                            state.custom_checks[cmd] = resp.result
                        except Exception as e:
                            state.custom_checks[cmd] = f"Error: {e}"

        except Exception as e:
            logger.error(f"Failed to capture state for {device_name}: {e}")
            raise

        return state

    @classmethod
    def _parse_interfaces(cls, output: str) -> list[dict]:
        """Parse 'show ip interface brief' output."""
        interfaces = []
        lines = output.strip().split("\n")

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                interfaces.append({
                    "name": parts[0],
                    "ip": parts[1],
                    "status": parts[4],
                    "protocol": parts[5],
                })

        return interfaces

    @classmethod
    def _parse_routes(cls, output: str) -> list[dict]:
        """Parse 'show ip route' output (simplified)."""
        routes = []
        import re

        for line in output.split("\n"):
            # Match route entries like: C    10.0.12.0/30 is directly connected
            match = re.match(r"^([A-Z*])\s+(\d+\.\d+\.\d+\.\d+/?\d*)", line)
            if match:
                routes.append({
                    "code": match.group(1),
                    "network": match.group(2),
                })

        return routes

    @classmethod
    def _parse_neighbors(cls, output: str) -> list[dict]:
        """Parse CDP neighbors output."""
        neighbors = []
        lines = output.strip().split("\n")

        for line in lines:
            # Skip headers and empty lines
            if "Device ID" in line or "---" in line or not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 2:
                neighbors.append({
                    "device_id": parts[0],
                    "local_interface": parts[1] if len(parts) > 1 else "",
                })

        return neighbors


# =============================================================================
# Validation Engine
# =============================================================================

class ValidationEngine:
    """Post-change validation engine."""

    @classmethod
    async def validate(
        cls,
        device_name: str,
        pre_state: PreChangeState,
        validation_checks: list[str],
    ) -> PostChangeValidation:
        """
        Validate changes against pre-state and custom checks.

        Args:
            device_name: Device to validate
            pre_state: State captured before change
            validation_checks: Commands to run for validation

        Returns:
            PostChangeValidation with results
        """
        from config.devices import DEVICES
        from core.scrapli_manager import get_ios_xe_connection

        validation = PostChangeValidation(
            device=device_name,
            validated_at=isonow(),
            overall_result=ValidationResult.PASSED,
        )

        try:
            async with get_ios_xe_connection(device_name) as conn:
                # Get new config for diff
                config_resp = await conn.send_command("show running-config")
                new_config = config_resp.result

                # Calculate config diff
                validation.config_diff = cls._diff_configs(
                    pre_state.running_config, new_config
                )

                # Get new interface status
                intf_resp = await conn.send_command("show ip interface brief")
                new_interfaces = StateCapture._parse_interfaces(intf_resp.result)
                validation.interface_changes = cls._diff_interfaces(
                    pre_state.interfaces, new_interfaces
                )

                # Get new routes
                route_resp = await conn.send_command("show ip route")
                new_routes = StateCapture._parse_routes(route_resp.result)
                validation.route_changes = cls._diff_routes(
                    pre_state.routes, new_routes
                )

                # Run validation checks
                for check in validation_checks:
                    try:
                        resp = await conn.send_command(check)
                        output = resp.result

                        # Determine if check passed
                        # For ping: look for success rate
                        # For show commands: just verify no error
                        passed = cls._evaluate_check(check, output)

                        validation.checks.append({
                            "command": check,
                            "result": "passed" if passed else "failed",
                            "output": output[:500],  # Truncate long output
                        })

                        if not passed:
                            validation.overall_result = ValidationResult.FAILED

                    except Exception as e:
                        validation.checks.append({
                            "command": check,
                            "result": "error",
                            "error": str(e),
                        })
                        validation.overall_result = ValidationResult.FAILED

        except Exception as e:
            logger.error(f"Validation failed for {device_name}: {e}")
            validation.overall_result = ValidationResult.ERROR
            validation.checks.append({
                "command": "connection",
                "result": "error",
                "error": str(e),
            })

        return validation

    @classmethod
    def _diff_configs(cls, old_config: str, new_config: str) -> list[str]:
        """Calculate config diff (added/removed lines)."""
        old_lines = set(l.strip() for l in old_config.split("\n") if l.strip() and not l.strip().startswith("!"))
        new_lines = set(l.strip() for l in new_config.split("\n") if l.strip() and not l.strip().startswith("!"))

        diff = []
        for line in new_lines - old_lines:
            diff.append(f"+ {line}")
        for line in old_lines - new_lines:
            diff.append(f"- {line}")

        return diff[:100]  # Limit to 100 lines

    @classmethod
    def _diff_interfaces(cls, old_intfs: list[dict], new_intfs: list[dict]) -> list[dict]:
        """Calculate interface changes."""
        changes = []
        old_map = {i["name"]: i for i in old_intfs}
        new_map = {i["name"]: i for i in new_intfs}

        # Check for changes
        for name, new_intf in new_map.items():
            if name not in old_map:
                changes.append({"interface": name, "change": "added", "new_state": new_intf})
            elif old_map[name] != new_intf:
                changes.append({
                    "interface": name,
                    "change": "modified",
                    "old_state": old_map[name],
                    "new_state": new_intf,
                })

        for name in old_map:
            if name not in new_map:
                changes.append({"interface": name, "change": "removed", "old_state": old_map[name]})

        return changes

    @classmethod
    def _diff_routes(cls, old_routes: list[dict], new_routes: list[dict]) -> list[dict]:
        """Calculate route changes."""
        changes = []
        old_set = {r["network"] for r in old_routes}
        new_set = {r["network"] for r in new_routes}

        for network in new_set - old_set:
            changes.append({"network": network, "change": "added"})
        for network in old_set - new_set:
            changes.append({"network": network, "change": "removed"})

        return changes

    @classmethod
    def _evaluate_check(cls, command: str, output: str) -> bool:
        """Evaluate if a validation check passed."""
        output_lower = output.lower()

        # Ping check
        if command.lower().startswith("ping"):
            # Success rate 100 percent or similar
            if "success rate is 100" in output_lower:
                return True
            if "success rate is 80" in output_lower or "success rate is 60" in output_lower:
                return True  # Partial success is OK for some checks
            if "!" in output and "." not in output:
                return True  # All pings succeeded
            return False

        # Show commands - just verify no error
        if "invalid" in output_lower or "error" in output_lower or "failed" in output_lower:
            return False

        return True


# =============================================================================
# Change Manager
# =============================================================================

class ChangeManager:
    """
    Manages change requests with pre/post validation and rollback.
    """

    def __init__(self, db_path: Path = None):
        self._dm = DatabaseManager.get_instance()

    async def create_change(
        self,
        device: str,
        description: str,
        commands: list[str],
        change_type: ChangeType = ChangeType.CONFIG,
        validation_checks: list[str] = None,
        rollback_commands: list[str] = None,
        created_by: str = "system",
        require_approval: bool = True,
        auto_rollback: bool = True,
    ) -> ChangeRequest:
        """
        Create a new change request.

        Args:
            device: Target device
            description: Change description
            commands: Config commands to execute
            change_type: Type of change
            validation_checks: Commands to run for validation
            rollback_commands: Commands to undo the change (auto-generated if not provided)
            created_by: User creating the change
            require_approval: Whether approval is needed
            auto_rollback: Whether to rollback on validation failure

        Returns:
            ChangeRequest with status DRAFT or PENDING_APPROVAL
        """
        change = ChangeRequest(
            id=str(uuid.uuid4())[:8],
            device=device,
            description=description,
            change_type=change_type,
            status=ChangeStatus.PENDING_APPROVAL if require_approval else ChangeStatus.APPROVED,
            commands=commands,
            validation_checks=validation_checks or [],
            rollback_commands=rollback_commands or self._generate_rollback(commands),
            created_at=isonow(),
            created_by=created_by,
            require_approval=require_approval,
            auto_rollback=auto_rollback,
        )

        self._save_change(change)
        logger.info(f"Created change request {change.id} for {device}")

        return change

    def _generate_rollback(self, commands: list[str]) -> list[str]:
        """Auto-generate rollback commands."""
        rollback = []

        for cmd in commands:
            cmd_lower = cmd.lower().strip()

            # Interface commands
            if cmd_lower.startswith("interface "):
                rollback.append(cmd)  # Enter same interface
            elif cmd_lower.startswith("no "):
                rollback.append(cmd[3:])  # Remove 'no' prefix
            elif cmd_lower.startswith("ip address"):
                rollback.append(f"no {cmd}")
            elif cmd_lower.startswith("shutdown"):
                rollback.append("no shutdown")
            elif cmd_lower.startswith("no shutdown"):
                rollback.append("shutdown")
            else:
                # Generic: prepend 'no'
                rollback.append(f"no {cmd}")

        return rollback

    async def approve_change(
        self,
        change_id: str,
        approved_by: str = "admin",
    ) -> ChangeRequest:
        """
        Approve a change request.

        Args:
            change_id: Change ID to approve
            approved_by: User approving the change

        Returns:
            Updated ChangeRequest
        """
        change = self.get_change(change_id)
        if not change:
            raise ValueError(f"Change '{change_id}' not found")

        if change.status not in (ChangeStatus.DRAFT, ChangeStatus.PENDING_APPROVAL):
            raise ValueError(f"Change '{change_id}' cannot be approved (status: {change.status})")

        change.status = ChangeStatus.APPROVED
        change.approved_at = isonow()
        change.approved_by = approved_by

        self._save_change(change)
        logger.info(f"Change {change_id} approved by {approved_by}")

        return change

    async def cancel_change(
        self,
        change_id: str,
        cancelled_by: str = "admin",
        reason: str = "",
    ) -> ChangeRequest:
        """
        Cancel a change request.

        Can only cancel changes that haven't been executed yet.

        Args:
            change_id: Change ID to cancel
            cancelled_by: User cancelling the change
            reason: Optional reason for cancellation

        Returns:
            Updated ChangeRequest
        """
        change = self.get_change(change_id)
        if not change:
            raise ValueError(f"Change '{change_id}' not found")

        # Can only cancel changes that haven't started execution
        cancellable_states = (
            ChangeStatus.DRAFT,
            ChangeStatus.PENDING_APPROVAL,
            ChangeStatus.APPROVED,
        )
        if change.status not in cancellable_states:
            raise ValueError(
                f"Change '{change_id}' cannot be cancelled (status: {change.status}). "
                f"Only draft, pending_approval, and approved changes can be cancelled."
            )

        change.status = ChangeStatus.CANCELLED
        change.completed_at = isonow()
        if reason:
            change.error = f"Cancelled by {cancelled_by}: {reason}"
        else:
            change.error = f"Cancelled by {cancelled_by}"

        self._save_change(change)
        logger.info(f"Change {change_id} cancelled by {cancelled_by}")

        return change

    async def execute_change(
        self,
        change_id: str,
        skip_pre_capture: bool = False,
        skip_validation: bool = False,
    ) -> ChangeRequest:
        """
        Execute a change with pre/post validation.

        Args:
            change_id: Change ID to execute
            skip_pre_capture: Skip pre-change state capture
            skip_validation: Skip post-change validation

        Returns:
            Updated ChangeRequest with results
        """
        from config.devices import DEVICES
        from core.scrapli_manager import get_ios_xe_connection

        change = self.get_change(change_id)
        if not change:
            raise ValueError(f"Change '{change_id}' not found")

        if change.status != ChangeStatus.APPROVED:
            raise ValueError(f"Change '{change_id}' is not approved (status: {change.status})")

        if change.device not in DEVICES:
            change.status = ChangeStatus.FAILED
            change.error = f"Device '{change.device}' not found"
            self._save_change(change)
            return change

        change.status = ChangeStatus.IN_PROGRESS
        change.executed_at = isonow()
        self._save_change(change)

        try:
            # 1. Capture pre-change state
            if not skip_pre_capture:
                logger.info(f"Capturing pre-change state for {change.device}")
                change.pre_state = await StateCapture.capture(
                    change.device,
                    change.validation_checks,
                )
                self._save_change(change)

            # 2. Execute commands
            logger.info(f"Executing {len(change.commands)} commands on {change.device}")
            async with get_ios_xe_connection(change.device) as conn:
                for cmd in change.commands:
                    try:
                        resp = await conn.send_config(cmd)
                        change.execution_output.append(f"{cmd}: OK")
                    except Exception as e:
                        change.execution_output.append(f"{cmd}: ERROR - {e}")
                        raise

            # 3. Post-change validation
            if not skip_validation and change.validation_checks:
                change.status = ChangeStatus.VALIDATING
                self._save_change(change)

                logger.info(f"Running post-change validation for {change.device}")
                change.post_validation = await ValidationEngine.validate(
                    change.device,
                    change.pre_state,
                    change.validation_checks,
                )

                if change.post_validation.overall_result == ValidationResult.FAILED:
                    logger.warning(f"Validation failed for change {change_id}")

                    if change.auto_rollback:
                        logger.info(f"Auto-rolling back change {change_id}")
                        await self._execute_rollback(change)
                        change.status = ChangeStatus.ROLLED_BACK
                        change.error = "Validation failed - auto-rollback executed"
                    else:
                        change.status = ChangeStatus.FAILED
                        change.error = "Validation failed"
                else:
                    change.status = ChangeStatus.COMPLETED
            else:
                change.status = ChangeStatus.COMPLETED

            change.completed_at = isonow()

        except Exception as e:
            logger.error(f"Change {change_id} failed: {e}")
            change.status = ChangeStatus.FAILED
            change.error = str(e)

            if change.auto_rollback and change.pre_state:
                try:
                    await self._execute_rollback(change)
                    change.status = ChangeStatus.ROLLED_BACK
                    change.error = f"Execution failed - auto-rollback executed: {e}"
                except Exception as rollback_error:
                    change.error = f"Execution failed and rollback failed: {e} / {rollback_error}"

        self._save_change(change)
        return change

    async def _execute_rollback(self, change: ChangeRequest):
        """Execute rollback commands."""
        from core.scrapli_manager import get_ios_xe_connection

        if not change.rollback_commands:
            logger.warning(f"No rollback commands for change {change.id}")
            return

        async with get_ios_xe_connection(change.device) as conn:
            for cmd in change.rollback_commands:
                try:
                    await conn.send_config(cmd)
                    change.execution_output.append(f"ROLLBACK: {cmd}: OK")
                except Exception as e:
                    change.execution_output.append(f"ROLLBACK: {cmd}: ERROR - {e}")
                    raise

    async def rollback_change(self, change_id: str) -> ChangeRequest:
        """
        Manually rollback a completed change.

        Args:
            change_id: Change ID to rollback

        Returns:
            Updated ChangeRequest
        """
        change = self.get_change(change_id)
        if not change:
            raise ValueError(f"Change '{change_id}' not found")

        if change.status not in (ChangeStatus.COMPLETED, ChangeStatus.FAILED):
            raise ValueError(f"Change '{change_id}' cannot be rolled back (status: {change.status})")

        try:
            await self._execute_rollback(change)
            change.status = ChangeStatus.ROLLED_BACK
            change.completed_at = isonow()
        except Exception as e:
            change.error = f"Rollback failed: {e}"

        self._save_change(change)
        return change

    def get_change(self, change_id: str) -> Optional[ChangeRequest]:
        """Get a change request by ID."""
        with self._dm.connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM changes WHERE id = ?", (change_id,)
            ).fetchone()

            if not row:
                return None

            return self._row_to_change(row)

    def list_changes(
        self,
        device: str = None,
        status: ChangeStatus = None,
        limit: int = 50,
    ) -> list[ChangeRequest]:
        """List change requests with optional filters."""
        query = "SELECT * FROM changes WHERE 1=1"
        params = []

        if device:
            query += " AND device = ?"
            params.append(device)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._dm.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_change(row) for row in rows]

    def _row_to_change(self, row: sqlite3.Row) -> ChangeRequest:
        """Convert database row to ChangeRequest."""
        pre_state = None
        if row["pre_state_json"]:
            ps_data = json.loads(row["pre_state_json"])
            pre_state = PreChangeState(**ps_data)

        post_validation = None
        if row["post_validation_json"]:
            pv_data = json.loads(row["post_validation_json"])
            pv_data["overall_result"] = ValidationResult(pv_data["overall_result"])
            post_validation = PostChangeValidation(**pv_data)

        return ChangeRequest(
            id=row["id"],
            device=row["device"],
            description=row["description"],
            change_type=ChangeType(row["change_type"]),
            status=ChangeStatus(row["status"]),
            commands=json.loads(row["commands_json"] or "[]"),
            validation_checks=json.loads(row["validation_checks_json"] or "[]"),
            rollback_commands=json.loads(row["rollback_commands_json"] or "[]"),
            pre_state=pre_state,
            post_validation=post_validation,
            created_at=row["created_at"],
            created_by=row["created_by"],
            approved_at=row["approved_at"],
            approved_by=row["approved_by"],
            executed_at=row["executed_at"],
            completed_at=row["completed_at"],
            error=row["error"],
            execution_output=json.loads(row["execution_output_json"] or "[]"),
            require_approval=bool(row["require_approval"]),
            auto_rollback=bool(row["auto_rollback"]),
        )

    def _save_change(self, change: ChangeRequest):
        """Save change request to database."""
        with self._dm.connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO changes VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                change.id,
                change.device,
                change.description,
                change.change_type.value,
                change.status.value,
                json.dumps(change.commands),
                json.dumps(change.validation_checks),
                json.dumps(change.rollback_commands),
                json.dumps(change.pre_state.to_dict()) if change.pre_state else None,
                json.dumps(change.post_validation.to_dict()) if change.post_validation else None,
                change.created_at,
                change.created_by,
                change.approved_at,
                change.approved_by,
                change.executed_at,
                change.completed_at,
                change.error,
                json.dumps(change.execution_output),
                1 if change.require_approval else 0,
                1 if change.auto_rollback else 0,
            ))


# =============================================================================
# Global Instance
# =============================================================================

_manager: Optional[ChangeManager] = None


def get_change_manager() -> ChangeManager:
    """Get the global change manager instance."""
    global _manager
    if _manager is None:
        _manager = ChangeManager()
    return _manager
