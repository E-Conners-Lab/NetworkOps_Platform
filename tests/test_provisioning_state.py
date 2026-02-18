"""
Unit tests for provisioning state management.

Tests the ProvisioningStateManager and ProvisioningJob classes.
"""

import json
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest


class TestJobStatus:
    """Tests for JobStatus enum."""

    def test_status_values(self):
        """All expected status values exist."""
        from core.provisioning.state import JobStatus

        assert JobStatus.PENDING.value == "pending"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.ROLLED_BACK.value == "rolled_back"
        assert JobStatus.CANCELLED.value == "cancelled"


class TestProvisioningJob:
    """Tests for ProvisioningJob dataclass."""

    def test_job_creation(self):
        """Job can be created with required fields."""
        from core.provisioning.state import JobStatus, ProvisioningJob

        job = ProvisioningJob(
            job_id="test-123",
            correlation_id="corr-456",
            device_name="R10",
            platform="eve-ng",
            status=JobStatus.PENDING,
        )

        assert job.job_id == "test-123"
        assert job.correlation_id == "corr-456"
        assert job.device_name == "R10"
        assert job.platform == "eve-ng"
        assert job.status == JobStatus.PENDING

    def test_job_to_dict(self):
        """Job can be serialized to dict."""
        from core.provisioning.state import JobStatus, ProvisioningJob

        job = ProvisioningJob(
            job_id="test-123",
            correlation_id="corr-456",
            device_name="R10",
            platform="eve-ng",
            status=JobStatus.RUNNING,
            step="creating_node",
            progress_pct=50,
        )

        data = job.to_dict()

        assert data["job_id"] == "test-123"
        assert data["status"] == "running"  # Enum converted to string
        assert data["step"] == "creating_node"
        assert data["progress_pct"] == 50

    def test_job_from_dict(self):
        """Job can be deserialized from dict."""
        from core.provisioning.state import JobStatus, ProvisioningJob

        data = {
            "job_id": "test-123",
            "correlation_id": "corr-456",
            "device_name": "R10",
            "platform": "eve-ng",
            "status": "completed",
            "step": "finalize",
            "progress_pct": 100,
            "steps_completed": ["step1", "step2"],
            "steps_remaining": [],
            "started_at": "2025-01-01T00:00:00",
            "completed_at": "2025-01-01T00:05:00",
            "error": "",
            "rollback_actions": [],
            "eve_ng_node_id": 15,
            "containerlab_node_name": None,
            "netbox_device_id": 42,
            "mgmt_ip": "10.255.255.50",
        }

        job = ProvisioningJob.from_dict(data)

        assert job.job_id == "test-123"
        assert job.status == JobStatus.COMPLETED
        assert job.eve_ng_node_id == 15
        assert job.mgmt_ip == "10.255.255.50"

    def test_job_default_values(self):
        """Job has correct default values."""
        from core.provisioning.state import JobStatus, ProvisioningJob

        job = ProvisioningJob(
            job_id="test",
            correlation_id="corr",
            device_name="R10",
            platform="eve-ng",
            status=JobStatus.PENDING,
        )

        assert job.step == ""
        assert job.progress_pct == 0
        assert job.steps_completed == []
        assert job.steps_remaining == []
        assert job.error == ""
        assert job.rollback_actions == []
        assert job.eve_ng_node_id is None


class TestProvisioningStateManager:
    """Tests for ProvisioningStateManager."""

    @pytest.fixture
    def temp_state_file(self):
        """Create temporary state file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            yield Path(f.name)

    @pytest.fixture
    def manager(self, temp_state_file):
        """Create state manager with temp file."""
        from core.provisioning.state import ProvisioningStateManager

        return ProvisioningStateManager(state_file=temp_state_file)

    def test_create_job(self, manager):
        """Creating a job returns valid job."""
        job = manager.create_job("R10", "eve-ng")

        assert job.job_id.startswith("prov-")
        assert job.correlation_id.startswith("corr-")
        assert job.device_name == "R10"
        assert job.platform == "eve-ng"
        assert len(job.steps_remaining) > 0

    def test_create_job_with_correlation_id(self, manager):
        """Custom correlation ID is used."""
        job = manager.create_job("R10", "eve-ng", correlation_id="user-123")

        assert job.correlation_id == "user-123"

    def test_create_job_eve_ng_steps(self, manager):
        """EVE-NG job has correct steps."""
        job = manager.create_job("R10", "eve-ng")

        assert "validate_inputs" in job.steps_remaining
        assert "create_node" in job.steps_remaining
        assert "wait_for_boot" in job.steps_remaining

    def test_create_job_containerlab_steps(self, manager):
        """Containerlab job has correct steps."""
        job = manager.create_job("server3", "containerlab")

        assert "validate_inputs" in job.steps_remaining
        assert "modify_topology" in job.steps_remaining
        assert "deploy_node" in job.steps_remaining

    def test_update_job_status(self, manager):
        """Job status can be updated."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        updated = manager.update_job(job.job_id, status=JobStatus.RUNNING)

        assert updated.status == JobStatus.RUNNING

    def test_update_job_step(self, manager):
        """Updating step moves previous step to completed."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        manager.update_job(job.job_id, status=JobStatus.RUNNING, step="validate_inputs")
        updated = manager.update_job(job.job_id, step="create_node")

        assert updated.step == "create_node"
        assert "validate_inputs" in updated.steps_completed
        assert updated.progress_pct > 0

    def test_update_job_not_found(self, manager):
        """Updating nonexistent job returns None."""
        result = manager.update_job("nonexistent", step="test")

        assert result is None

    def test_add_rollback_action(self, manager):
        """Rollback actions are added to job."""
        job = manager.create_job("R10", "eve-ng")
        action = {"action": "delete_node", "node_id": 15}

        result = manager.add_rollback_action(job.job_id, action)

        assert result is True
        job = manager.get_job(job.job_id)
        assert len(job.rollback_actions) == 1
        assert job.rollback_actions[0]["action"] == "delete_node"

    def test_complete_job(self, manager):
        """Completing job sets status and clears remaining steps."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        completed = manager.complete_job(job.job_id)

        assert completed.status == JobStatus.COMPLETED
        assert completed.progress_pct == 100
        assert len(completed.steps_remaining) == 0
        assert completed.completed_at != ""

    def test_fail_job(self, manager):
        """Failing job sets error message."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        failed = manager.fail_job(job.job_id, "Connection timeout")

        assert failed.status == JobStatus.FAILED
        assert failed.error == "Connection timeout"
        assert failed.completed_at != ""

    def test_cancel_job(self, manager):
        """Pending/running job can be cancelled."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        cancelled = manager.cancel_job(job.job_id)

        assert cancelled.status == JobStatus.CANCELLED

    def test_cancel_completed_job(self, manager):
        """Completed job cannot be cancelled."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        manager.complete_job(job.job_id)
        result = manager.cancel_job(job.job_id)

        assert result.status == JobStatus.COMPLETED  # Still completed

    def test_mark_rolled_back(self, manager):
        """Job can be marked as rolled back."""
        from core.provisioning.state import JobStatus

        job = manager.create_job("R10", "eve-ng")
        manager.fail_job(job.job_id, "Test error")
        rolled = manager.mark_rolled_back(job.job_id)

        assert rolled.status == JobStatus.ROLLED_BACK

    def test_get_job(self, manager):
        """Job can be retrieved by ID."""
        job = manager.create_job("R10", "eve-ng")
        retrieved = manager.get_job(job.job_id)

        assert retrieved.job_id == job.job_id
        assert retrieved.device_name == "R10"

    def test_get_job_not_found(self, manager):
        """Getting nonexistent job returns None."""
        result = manager.get_job("nonexistent")

        assert result is None

    def test_list_jobs(self, manager):
        """Jobs can be listed with filters."""
        from core.provisioning.state import JobStatus

        job1 = manager.create_job("R10", "eve-ng")
        job2 = manager.create_job("R11", "containerlab")
        manager.update_job(job1.job_id, status=JobStatus.RUNNING)
        manager.complete_job(job2.job_id)

        # Filter by status
        running = manager.list_jobs(status=JobStatus.RUNNING)
        assert len(running) == 1
        assert running[0].device_name == "R10"

        # Filter by platform
        containerlab = manager.list_jobs(platform="containerlab")
        assert len(containerlab) == 1
        assert containerlab[0].device_name == "R11"

    def test_get_active_jobs(self, manager):
        """Active jobs are pending or running."""
        from core.provisioning.state import JobStatus

        job1 = manager.create_job("R10", "eve-ng")
        job2 = manager.create_job("R11", "eve-ng")
        manager.update_job(job1.job_id, status=JobStatus.RUNNING)
        manager.complete_job(job2.job_id)

        active = manager.get_active_jobs()

        assert len(active) == 1
        assert active[0].device_name == "R10"

    def test_get_rollback_actions_reversed(self, manager):
        """Rollback actions are returned in reverse order."""
        job = manager.create_job("R10", "eve-ng")
        manager.add_rollback_action(job.job_id, {"action": "step1", "order": 1})
        manager.add_rollback_action(job.job_id, {"action": "step2", "order": 2})
        manager.add_rollback_action(job.job_id, {"action": "step3", "order": 3})

        actions = manager.get_rollback_actions(job.job_id)

        assert len(actions) == 3
        assert actions[0]["order"] == 3  # Reversed
        assert actions[1]["order"] == 2
        assert actions[2]["order"] == 1

    def test_persistence(self, temp_state_file):
        """State persists across manager instances."""
        from core.provisioning.state import JobStatus, ProvisioningStateManager

        # Create and update job
        manager1 = ProvisioningStateManager(state_file=temp_state_file)
        job = manager1.create_job("R10", "eve-ng")
        manager1.update_job(job.job_id, status=JobStatus.RUNNING, step="creating_node")

        # Load in new manager
        manager2 = ProvisioningStateManager(state_file=temp_state_file)
        loaded = manager2.get_job(job.job_id)

        assert loaded is not None
        assert loaded.status == JobStatus.RUNNING
        assert loaded.step == "creating_node"

    def test_get_stats(self, manager):
        """Stats are calculated correctly."""
        from core.provisioning.state import JobStatus

        manager.create_job("R10", "eve-ng")
        job2 = manager.create_job("R11", "eve-ng")
        job3 = manager.create_job("server1", "containerlab")
        manager.update_job(job2.job_id, status=JobStatus.RUNNING)
        manager.complete_job(job3.job_id)

        stats = manager.get_stats()

        assert stats["total_jobs"] == 3
        assert stats["by_status"]["pending"] == 1
        assert stats["by_status"]["running"] == 1
        assert stats["by_status"]["completed"] == 1
        assert stats["by_platform"]["eve-ng"] == 2
        assert stats["by_platform"]["containerlab"] == 1
        assert stats["active_jobs"] == 2


class TestStaleJobCleanup:
    """Tests for stale job cleanup."""

    def test_cleanup_stale_jobs(self):
        """Old running jobs are marked as stale."""
        import tempfile

        from core.provisioning.state import JobStatus, ProvisioningStateManager

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            state_file = Path(f.name)

        # Create manager with 0 hour timeout (all running jobs are stale)
        manager = ProvisioningStateManager(
            state_file=state_file, stale_timeout_hours=0
        )

        job = manager.create_job("R10", "eve-ng")
        manager.update_job(job.job_id, status=JobStatus.RUNNING)

        # Wait a tiny bit so the job is "old"
        time.sleep(0.1)

        stale = manager.cleanup_stale_jobs()

        assert len(stale) == 1
        assert stale[0].status == JobStatus.FAILED
        assert "stale" in stale[0].error.lower()


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_updates(self):
        """Multiple threads can update state safely."""
        import tempfile
        import threading

        from core.provisioning.state import JobStatus, ProvisioningStateManager

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            state_file = Path(f.name)

        manager = ProvisioningStateManager(state_file=state_file)
        errors = []

        def update_job(job_id, step):
            try:
                manager.update_job(job_id, status=JobStatus.RUNNING, step=step)
            except Exception as e:
                errors.append(e)

        # Create job
        job = manager.create_job("R10", "eve-ng")

        # Update from multiple threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=update_job, args=(job.job_id, f"step_{i}"))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0

        # Job should still be retrievable
        result = manager.get_job(job.job_id)
        assert result is not None
