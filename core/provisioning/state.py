"""
Provisioning state management.

Tracks async provisioning jobs with persistence, rollback actions,
and cleanup capabilities.

State is persisted to JSON file for recovery across server restarts.
"""

import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from core.timestamps import isonow, now, parse_timestamp
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Provisioning job status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


@dataclass
class ProvisioningJob:
    """
    A single provisioning job with full tracking.

    Attributes:
        job_id: Unique job identifier (UUID)
        correlation_id: User-provided correlation ID for log tracing
        device_name: Target device name
        platform: "eve-ng" or "containerlab"
        status: Current job status
        step: Current step being executed
        progress_pct: Progress percentage (0-100)
        steps_completed: List of completed step names
        steps_remaining: List of remaining step names
        started_at: Job start timestamp (ISO format)
        completed_at: Job completion timestamp (ISO format)
        error: Error message if failed
        rollback_actions: Ordered list of rollback actions
        eve_ng_node_id: EVE-NG node ID (for cleanup)
        containerlab_node_name: Containerlab node name (for cleanup)
        netbox_device_id: NetBox device ID (for cleanup)
        mgmt_ip: Assigned management IP address
    """

    job_id: str
    correlation_id: str
    device_name: str
    platform: str
    status: JobStatus
    step: str = ""
    progress_pct: int = 0
    steps_completed: List[str] = field(default_factory=list)
    steps_remaining: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    error: str = ""
    rollback_actions: List[Dict[str, Any]] = field(default_factory=list)
    eve_ng_node_id: Optional[int] = None
    containerlab_node_name: Optional[str] = None
    netbox_device_id: Optional[int] = None
    mgmt_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvisioningJob":
        """Create from dictionary (JSON deserialization)."""
        data["status"] = JobStatus(data["status"])
        return cls(**data)


class ProvisioningStateManager:
    """
    Manages provisioning job state with persistence.

    Thread-safe implementation using locks for concurrent access.

    Usage:
        manager = ProvisioningStateManager()

        # Create and track a job
        job = manager.create_job("R10", "eve-ng", correlation_id="user-123")
        manager.update_job(job.job_id, status=JobStatus.RUNNING)
        manager.complete_job(job.job_id)

        # Get job status
        status = manager.get_job(job_id)

        # Cleanup stale jobs on startup
        stale = manager.cleanup_stale_jobs()
    """

    # Default step definitions per platform
    EVE_NG_STEPS = [
        "validate_inputs",
        "allocate_ip",
        "create_node",
        "connect_interface",
        "start_node",
        "wait_for_boot",
        "apply_ztp",
        "add_to_netbox",
        "finalize",
    ]

    CONTAINERLAB_STEPS = [
        "validate_inputs",
        "allocate_ip",
        "backup_topology",
        "modify_topology",
        "deploy_node",
        "wait_for_boot",
        "add_to_netbox",
        "finalize",
    ]

    def __init__(
        self,
        state_file: Optional[Path] = None,
        stale_timeout_hours: int = 2,
        max_history: int = 100,
    ):
        """
        Initialize state manager.

        Args:
            state_file: Path to state JSON file (default: data/provisioning_state.json)
            stale_timeout_hours: Hours after which running jobs are considered stale
            max_history: Maximum completed/failed jobs to retain
        """
        self.state_file = state_file or Path("data/provisioning_state.json")
        self.stale_timeout_hours = stale_timeout_hours
        self.max_history = max_history

        self._jobs: Dict[str, ProvisioningJob] = {}
        self._lock = threading.RLock()

        # Ensure data directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing state
        self._load_state()

    def _load_state(self) -> None:
        """Load state from disk."""
        if not self.state_file.exists():
            logger.info("No existing state file, starting fresh")
            return

        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)

            for job_data in data.get("jobs", []):
                try:
                    job = ProvisioningJob.from_dict(job_data)
                    self._jobs[job.job_id] = job
                except Exception as e:
                    logger.warning(f"Failed to load job: {e}")

            logger.info(f"Loaded {len(self._jobs)} jobs from state file")

        except json.JSONDecodeError as e:
            logger.error(f"Corrupted state file: {e}")
        except Exception as e:
            logger.error(f"Failed to load state: {e}")

    def _save_state(self) -> None:
        """Persist state to disk."""
        try:
            data = {
                "updated_at": isonow(),
                "jobs": [job.to_dict() for job in self._jobs.values()],
            }

            # Write atomically using temp file
            temp_file = self.state_file.with_suffix(".tmp")
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)

            temp_file.replace(self.state_file)

        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _generate_job_id(self) -> str:
        """Generate unique job ID."""
        return f"prov-{uuid.uuid4().hex[:8]}"

    def _generate_correlation_id(self) -> str:
        """Generate correlation ID if not provided."""
        return f"corr-{uuid.uuid4().hex[:8]}"

    def create_job(
        self,
        device_name: str,
        platform: str,
        correlation_id: Optional[str] = None,
    ) -> ProvisioningJob:
        """
        Create a new provisioning job.

        Args:
            device_name: Name of device to provision
            platform: "eve-ng" or "containerlab"
            correlation_id: Optional user-provided correlation ID

        Returns:
            New ProvisioningJob instance
        """
        with self._lock:
            job_id = self._generate_job_id()
            corr_id = correlation_id or self._generate_correlation_id()

            # Determine steps based on platform
            if platform == "eve-ng":
                steps = self.EVE_NG_STEPS.copy()
            elif platform == "containerlab":
                steps = self.CONTAINERLAB_STEPS.copy()
            else:
                steps = ["validate_inputs", "provision", "finalize"]

            job = ProvisioningJob(
                job_id=job_id,
                correlation_id=corr_id,
                device_name=device_name,
                platform=platform,
                status=JobStatus.PENDING,
                step="",
                progress_pct=0,
                steps_completed=[],
                steps_remaining=steps,
                started_at=isonow(),
            )

            self._jobs[job_id] = job
            self._save_state()

            logger.info(
                f"[{corr_id}] Created provisioning job {job_id} "
                f"for {device_name} on {platform}"
            )

            return job

    def update_job(
        self,
        job_id: str,
        status: Optional[JobStatus] = None,
        step: Optional[str] = None,
        progress_pct: Optional[int] = None,
        error: Optional[str] = None,
        **kwargs,
    ) -> Optional[ProvisioningJob]:
        """
        Update job state.

        Args:
            job_id: Job to update
            status: New status
            step: Current step name
            progress_pct: Progress percentage
            error: Error message
            **kwargs: Additional fields to update

        Returns:
            Updated job or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                logger.warning(f"Job {job_id} not found")
                return None

            if status:
                job.status = status

            if step:
                # Move completed step to done list
                if job.step and job.step in job.steps_remaining:
                    job.steps_completed.append(job.step)
                    job.steps_remaining.remove(job.step)

                job.step = step

                # Calculate progress
                total_steps = len(job.steps_completed) + len(job.steps_remaining)
                if total_steps > 0:
                    job.progress_pct = int(
                        (len(job.steps_completed) / total_steps) * 100
                    )

            if progress_pct is not None:
                job.progress_pct = progress_pct

            if error:
                job.error = error

            # Update any additional fields
            for key, value in kwargs.items():
                if hasattr(job, key):
                    setattr(job, key, value)

            self._save_state()

            logger.info(
                f"[{job.correlation_id}] Job {job_id} updated: "
                f"status={job.status.value}, step={job.step}"
            )

            return job

    def add_rollback_action(
        self,
        job_id: str,
        action: Dict[str, Any],
    ) -> bool:
        """
        Add a rollback action to the job.

        Actions are stored in order and executed in reverse during rollback.

        Args:
            job_id: Job to add action to
            action: Dict with action details (action, platform, resource_id, etc.)

        Returns:
            True if added, False if job not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False

            job.rollback_actions.append(action)
            self._save_state()

            logger.debug(
                f"[{job.correlation_id}] Added rollback action: {action.get('action')}"
            )

            return True

    def complete_job(self, job_id: str) -> Optional[ProvisioningJob]:
        """
        Mark job as completed successfully.

        Args:
            job_id: Job to complete

        Returns:
            Updated job or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None

            job.status = JobStatus.COMPLETED
            job.completed_at = isonow()
            job.progress_pct = 100

            # Move any remaining steps to completed
            if job.step and job.step in job.steps_remaining:
                job.steps_completed.append(job.step)
                job.steps_remaining.remove(job.step)
            job.steps_completed.extend(job.steps_remaining)
            job.steps_remaining = []

            self._save_state()
            self._prune_old_jobs()

            logger.info(
                f"[{job.correlation_id}] Job {job_id} completed successfully"
            )

            return job

    def fail_job(self, job_id: str, error: str) -> Optional[ProvisioningJob]:
        """
        Mark job as failed.

        Args:
            job_id: Job to fail
            error: Error message

        Returns:
            Updated job or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None

            job.status = JobStatus.FAILED
            job.error = error
            job.completed_at = isonow()

            self._save_state()
            self._prune_old_jobs()

            logger.error(
                f"[{job.correlation_id}] Job {job_id} failed: {error}"
            )

            return job

    def mark_rolled_back(self, job_id: str) -> Optional[ProvisioningJob]:
        """
        Mark job as rolled back.

        Args:
            job_id: Job to mark

        Returns:
            Updated job or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None

            job.status = JobStatus.ROLLED_BACK
            job.completed_at = isonow()

            self._save_state()

            logger.info(
                f"[{job.correlation_id}] Job {job_id} rolled back"
            )

            return job

    def cancel_job(self, job_id: str) -> Optional[ProvisioningJob]:
        """
        Cancel a pending or running job.

        Args:
            job_id: Job to cancel

        Returns:
            Updated job or None if not found
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None

            if job.status not in (JobStatus.PENDING, JobStatus.RUNNING):
                logger.warning(
                    f"Cannot cancel job {job_id} in status {job.status.value}"
                )
                return job

            job.status = JobStatus.CANCELLED
            job.completed_at = isonow()

            self._save_state()

            logger.info(
                f"[{job.correlation_id}] Job {job_id} cancelled"
            )

            return job

    def get_job(self, job_id: str) -> Optional[ProvisioningJob]:
        """
        Get job by ID.

        Args:
            job_id: Job ID

        Returns:
            Job or None if not found
        """
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        platform: Optional[str] = None,
        device_name: Optional[str] = None,
        limit: int = 50,
    ) -> List[ProvisioningJob]:
        """
        List jobs with optional filters.

        Args:
            status: Filter by status
            platform: Filter by platform
            device_name: Filter by device name
            limit: Maximum jobs to return

        Returns:
            List of matching jobs (newest first)
        """
        with self._lock:
            jobs = list(self._jobs.values())

            if status:
                jobs = [j for j in jobs if j.status == status]

            if platform:
                jobs = [j for j in jobs if j.platform == platform]

            if device_name:
                jobs = [j for j in jobs if j.device_name == device_name]

            # Sort by started_at descending
            jobs.sort(key=lambda j: j.started_at, reverse=True)

            return jobs[:limit]

    def get_active_jobs(self) -> List[ProvisioningJob]:
        """Get all pending or running jobs."""
        return self.list_jobs(status=JobStatus.RUNNING) + self.list_jobs(
            status=JobStatus.PENDING
        )

    def cleanup_stale_jobs(self) -> List[ProvisioningJob]:
        """
        Find and mark stale running jobs as failed.

        Jobs are considered stale if they've been running longer than
        stale_timeout_hours without updates.

        Returns:
            List of jobs that were marked as stale
        """
        with self._lock:
            stale_jobs = []
            cutoff = now() - timedelta(hours=self.stale_timeout_hours)

            for job in self._jobs.values():
                if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
                    try:
                        started = parse_timestamp(job.started_at)
                        if started < cutoff:
                            job.status = JobStatus.FAILED
                            job.error = f"Job stale after {self.stale_timeout_hours}h"
                            job.completed_at = isonow()
                            stale_jobs.append(job)
                            logger.warning(
                                f"[{job.correlation_id}] Marked job {job.job_id} as stale"
                            )
                    except ValueError:
                        pass

            if stale_jobs:
                self._save_state()

            return stale_jobs

    def _prune_old_jobs(self) -> None:
        """Remove old completed/failed jobs beyond max_history."""
        completed_statuses = {
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.ROLLED_BACK,
            JobStatus.CANCELLED,
        }

        completed_jobs = [
            j for j in self._jobs.values() if j.status in completed_statuses
        ]

        if len(completed_jobs) > self.max_history:
            # Sort by completed_at and remove oldest
            completed_jobs.sort(key=lambda j: j.completed_at or "", reverse=True)
            for job in completed_jobs[self.max_history :]:
                del self._jobs[job.job_id]
                logger.debug(f"Pruned old job {job.job_id}")

    def get_rollback_actions(self, job_id: str) -> List[Dict[str, Any]]:
        """
        Get rollback actions for a job in reverse order.

        Args:
            job_id: Job ID

        Returns:
            List of rollback actions (reverse order for execution)
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return []

            # Return in reverse order for proper rollback sequence
            return list(reversed(job.rollback_actions))

    def get_stats(self) -> Dict[str, Any]:
        """
        Get state manager statistics.

        Returns:
            Dict with job counts by status and platform
        """
        with self._lock:
            stats = {
                "total_jobs": len(self._jobs),
                "by_status": {},
                "by_platform": {},
                "active_jobs": 0,
            }

            for job in self._jobs.values():
                # Count by status
                status = job.status.value
                stats["by_status"][status] = stats["by_status"].get(status, 0) + 1

                # Count by platform
                stats["by_platform"][job.platform] = (
                    stats["by_platform"].get(job.platform, 0) + 1
                )

                # Count active
                if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
                    stats["active_jobs"] += 1

            return stats
