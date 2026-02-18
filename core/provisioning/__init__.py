"""
Provisioning state management and job tracking.

This package provides async infrastructure for device provisioning workflows:
- Job state management with persistence
- Correlation IDs for log tracing
- Rollback action tracking
- Cleanup of stale jobs

Usage:
    from core.provisioning import ProvisioningStateManager, JobStatus

    manager = ProvisioningStateManager()

    # Create a new provisioning job
    job = manager.create_job(
        device_name="R10",
        platform="eve-ng",
        correlation_id="user-123-1234567890"
    )

    # Update job status
    manager.update_job(job.job_id, status=JobStatus.RUNNING, step="creating_node")

    # Track rollback actions
    manager.add_rollback_action(job.job_id, {
        "action": "delete_node",
        "platform": "eve-ng",
        "node_id": 15
    })

    # Complete or fail the job
    manager.complete_job(job.job_id)
    manager.fail_job(job.job_id, error="Connection timeout")
"""

from core.provisioning.state import (
    JobStatus,
    ProvisioningJob,
    ProvisioningStateManager,
)
from core.provisioning.executor import (
    ProvisioningExecutor,
    get_executor,
)

__all__ = [
    "JobStatus",
    "ProvisioningJob",
    "ProvisioningStateManager",
    "ProvisioningExecutor",
    "get_executor",
]
