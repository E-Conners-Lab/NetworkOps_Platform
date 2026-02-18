"""
Scheduled Jobs System for NetworkOps.

Provides cron-like scheduling for recurring network tasks:
- Health checks
- Config backups
- Compliance audits
- Custom commands
- Report generation

Uses APScheduler with SQLite persistence for portability.
No external dependencies (Redis/Celery) required.

Usage:
    from core.scheduler import scheduler, create_job, list_jobs

    # Create a scheduled health check
    job = await create_job(
        name="Daily Health Check",
        job_type="health_check_all",
        schedule="0 6 * * *",  # 6 AM daily
    )

    # List all jobs
    jobs = await list_jobs()
"""

import asyncio
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from core.timestamps import isonow, now
from enum import Enum
from pathlib import Path
from typing import Optional, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = Path(os.getenv("DATA_PATH", Path(__file__).parent.parent / "data"))
SCHEDULER_DB = DATA_DIR / "scheduler.db"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Data Models
# =============================================================================

class JobType(str, Enum):
    """Supported job types."""
    HEALTH_CHECK = "health_check"
    HEALTH_CHECK_ALL = "health_check_all"
    BACKUP_CONFIG = "backup_config"
    BACKUP_ALL = "backup_all"
    COMPLIANCE_CHECK = "compliance_check"
    SEND_COMMAND = "send_command"
    BULK_COMMAND = "bulk_command"
    LLDP_DISCOVERY = "lldp_discovery"
    SNMP_POLL = "snmp_poll"
    DAILY_REPORT = "daily_report"
    CUSTOM = "custom"


class JobStatus(str, Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class ScheduledJob:
    """Scheduled job definition."""
    id: str
    name: str
    job_type: str
    schedule: str  # Cron expression or interval
    schedule_type: str = "cron"  # "cron" or "interval"
    params: dict = field(default_factory=dict)
    enabled: bool = True
    created_at: str = ""
    last_run: Optional[str] = None
    last_status: str = "pending"
    last_result: Optional[str] = None
    run_count: int = 0
    error_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "job_type": self.job_type,
            "schedule": self.schedule,
            "schedule_type": self.schedule_type,
            "params": self.params,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "last_status": self.last_status,
            "last_result": self.last_result,
            "run_count": self.run_count,
            "error_count": self.error_count,
        }


# =============================================================================
# Database Schema
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    schedule TEXT NOT NULL,
    schedule_type TEXT DEFAULT 'cron',
    params TEXT DEFAULT '{}',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    last_run TEXT,
    last_status TEXT DEFAULT 'pending',
    last_result TEXT,
    run_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS job_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT,
    duration_seconds REAL,
    FOREIGN KEY (job_id) REFERENCES scheduled_jobs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_job_history_job_id ON job_history(job_id);
CREATE INDEX IF NOT EXISTS idx_job_history_started ON job_history(started_at);
"""


@contextmanager
def get_db():
    """Get database connection with context manager."""
    conn = sqlite3.connect(str(SCHEDULER_DB))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Initialize database schema."""
    with get_db() as conn:
        conn.executescript(SCHEMA)
    logger.info(f"Scheduler database initialized: {SCHEDULER_DB}")


# =============================================================================
# Job Executors
# =============================================================================

async def execute_health_check(device_name: str) -> dict:
    """Execute health check on a single device."""
    from network_mcp_async import health_check
    result = await health_check(device_name)
    return json.loads(result)


async def execute_health_check_all() -> dict:
    """Execute health check on all devices."""
    from network_mcp_async import health_check_all
    result = await health_check_all()
    return json.loads(result)


async def execute_backup_config(device_name: str, label: str = None) -> dict:
    """Backup device configuration."""
    from network_mcp_async import backup_config
    result = await backup_config(device_name, label)
    return json.loads(result)


async def execute_backup_all(label: str = None) -> dict:
    """Backup all device configurations."""
    from config.devices import DEVICES, is_cisco_device
    from network_mcp_async import backup_config

    results = []
    for device_name in DEVICES:
        if is_cisco_device(device_name):
            try:
                result = await backup_config(device_name, label)
                results.append({"device": device_name, "result": json.loads(result)})
            except Exception as e:
                results.append({"device": device_name, "error": str(e)})

    return {"backups": results, "total": len(results)}


async def execute_compliance_check(device_name: str, template: str = "default") -> dict:
    """Run compliance check against golden template."""
    from mcp_tools.compliance import compliance_check
    result = await compliance_check(device_name, template)
    return json.loads(result)


async def execute_send_command(device_name: str, command: str) -> dict:
    """Send command to device."""
    from network_mcp_async import send_command
    result = await send_command(device_name, command)
    return json.loads(result)


async def execute_bulk_command(command: str, devices: str = None) -> dict:
    """Send command to multiple devices."""
    from network_mcp_async import bulk_command
    result = await bulk_command(command, devices)
    return json.loads(result)


async def execute_lldp_discovery() -> dict:
    """Run LLDP topology discovery."""
    from core.lldp import discover_lldp_topology
    return await discover_lldp_topology()


async def execute_snmp_poll(device_name: str = None) -> dict:
    """Poll device(s) via SNMP."""
    if device_name:
        from network_mcp_async import snmp_poll_metrics
        result = await snmp_poll_metrics(device_name)
    else:
        from network_mcp_async import snmp_poll_all_devices
        result = await snmp_poll_all_devices()
    return json.loads(result)


async def execute_daily_report() -> dict:
    """Generate the agent daily report."""
    from agents.reporting.daily_report import get_report_generator
    generator = get_report_generator()
    report = await generator.generate()
    return report.to_dict()


# Job type to executor mapping
JOB_EXECUTORS = {
    JobType.HEALTH_CHECK: execute_health_check,
    JobType.HEALTH_CHECK_ALL: execute_health_check_all,
    JobType.BACKUP_CONFIG: execute_backup_config,
    JobType.BACKUP_ALL: execute_backup_all,
    JobType.COMPLIANCE_CHECK: execute_compliance_check,
    JobType.SEND_COMMAND: execute_send_command,
    JobType.BULK_COMMAND: execute_bulk_command,
    JobType.LLDP_DISCOVERY: execute_lldp_discovery,
    JobType.SNMP_POLL: execute_snmp_poll,
    JobType.DAILY_REPORT: execute_daily_report,
}


# =============================================================================
# Scheduler Class
# =============================================================================

class NetworkScheduler:
    """Manages scheduled network automation jobs."""

    def __init__(self):
        self._scheduler: Optional[AsyncIOScheduler] = None
        self._running = False

    @property
    def scheduler(self) -> AsyncIOScheduler:
        """Get or create the scheduler instance."""
        if self._scheduler is None:
            jobstores = {
                'default': SQLAlchemyJobStore(url=f'sqlite:///{SCHEDULER_DB}')
            }
            executors = {
                'default': AsyncIOExecutor()
            }
            job_defaults = {
                'coalesce': True,  # Combine missed runs into one
                'max_instances': 1,  # Only one instance at a time
                'misfire_grace_time': 300,  # 5 minute grace period
            }
            self._scheduler = AsyncIOScheduler(
                jobstores=jobstores,
                executors=executors,
                job_defaults=job_defaults,
                timezone='UTC'
            )
        return self._scheduler

    def start(self):
        """Start the scheduler."""
        if not self._running:
            init_db()
            self._load_jobs()
            self.scheduler.start()
            self._running = True
            logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler."""
        if self._running:
            self.scheduler.shutdown()
            self._running = False
            logger.info("Scheduler stopped")

    def _load_jobs(self):
        """Load enabled jobs from database into scheduler."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE enabled = 1"
            )
            for row in cursor.fetchall():
                job = ScheduledJob(
                    id=row["id"],
                    name=row["name"],
                    job_type=row["job_type"],
                    schedule=row["schedule"],
                    schedule_type=row["schedule_type"],
                    params=json.loads(row["params"]),
                    enabled=bool(row["enabled"]),
                    created_at=row["created_at"],
                )
                self._add_job_to_scheduler(job)

    def _add_job_to_scheduler(self, job: ScheduledJob):
        """Add a job to the APScheduler."""
        # Create trigger
        if job.schedule_type == "interval":
            # Parse interval (e.g., "300" for 300 seconds, "5m", "1h")
            seconds = self._parse_interval(job.schedule)
            trigger = IntervalTrigger(seconds=seconds)
        else:
            # Cron expression
            trigger = CronTrigger.from_crontab(job.schedule)

        # Add to scheduler
        self.scheduler.add_job(
            self._execute_job,
            trigger=trigger,
            id=job.id,
            name=job.name,
            args=[job.id],
            replace_existing=True,
        )
        logger.info(f"Scheduled job: {job.name} ({job.schedule})")

    def _parse_interval(self, interval: str) -> int:
        """Parse interval string to seconds."""
        interval = interval.strip().lower()
        if interval.endswith('s'):
            return int(interval[:-1])
        elif interval.endswith('m'):
            return int(interval[:-1]) * 60
        elif interval.endswith('h'):
            return int(interval[:-1]) * 3600
        elif interval.endswith('d'):
            return int(interval[:-1]) * 86400
        else:
            return int(interval)

    async def _execute_job(self, job_id: str):
        """Execute a scheduled job."""
        start_time = now()

        # Get job definition
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,)
            )
            row = cursor.fetchone()
            if not row:
                logger.error(f"Job not found: {job_id}")
                return

        job_type = row["job_type"]
        params = json.loads(row["params"])

        logger.info(f"Executing scheduled job: {row['name']} ({job_type})")

        # Update status to running
        with get_db() as conn:
            conn.execute(
                "UPDATE scheduled_jobs SET last_status = 'running' WHERE id = ?",
                (job_id,)
            )

        try:
            # Get executor
            executor = JOB_EXECUTORS.get(job_type)
            if not executor:
                raise ValueError(f"Unknown job type: {job_type}")

            # Execute
            result = await executor(**params)

            # Record success
            end_time = now()
            duration = (end_time - start_time).total_seconds()

            with get_db() as conn:
                conn.execute("""
                    UPDATE scheduled_jobs
                    SET last_run = ?, last_status = 'success',
                        last_result = ?, run_count = run_count + 1
                    WHERE id = ?
                """, (end_time.isoformat(), json.dumps(result)[:10000], job_id))

                conn.execute("""
                    INSERT INTO job_history (job_id, started_at, completed_at, status, result, duration_seconds)
                    VALUES (?, ?, ?, 'success', ?, ?)
                """, (job_id, start_time.isoformat(), end_time.isoformat(), json.dumps(result)[:10000], duration))

            logger.info(f"Job completed: {row['name']} ({duration:.2f}s)")

        except Exception as e:
            # Record failure
            end_time = now()
            duration = (end_time - start_time).total_seconds()
            error_msg = str(e)

            with get_db() as conn:
                conn.execute("""
                    UPDATE scheduled_jobs
                    SET last_run = ?, last_status = 'failed',
                        last_result = ?, run_count = run_count + 1, error_count = error_count + 1
                    WHERE id = ?
                """, (end_time.isoformat(), error_msg[:10000], job_id))

                conn.execute("""
                    INSERT INTO job_history (job_id, started_at, completed_at, status, error, duration_seconds)
                    VALUES (?, ?, ?, 'failed', ?, ?)
                """, (job_id, start_time.isoformat(), end_time.isoformat(), error_msg[:10000], duration))

            logger.error(f"Job failed: {row['name']} - {error_msg}")


# Global scheduler instance
_scheduler: Optional[NetworkScheduler] = None


def get_scheduler() -> NetworkScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = NetworkScheduler()
    return _scheduler


# =============================================================================
# Public API Functions
# =============================================================================

async def create_job(
    name: str,
    job_type: str,
    schedule: str,
    schedule_type: str = "cron",
    params: dict = None,
    enabled: bool = True,
) -> ScheduledJob:
    """
    Create a new scheduled job.

    Args:
        name: Human-readable job name
        job_type: Type from JobType enum (health_check, backup_config, etc.)
        schedule: Cron expression ("0 6 * * *") or interval ("5m", "1h", "300")
        schedule_type: "cron" or "interval"
        params: Job-specific parameters (device_name, command, etc.)
        enabled: Whether to start the job immediately

    Returns:
        ScheduledJob instance
    """
    import uuid

    # Validate job type
    if job_type not in [j.value for j in JobType]:
        raise ValueError(f"Invalid job type: {job_type}. Valid types: {[j.value for j in JobType]}")

    job_id = str(uuid.uuid4())[:8]
    created_at = isonow()
    params = params or {}

    job = ScheduledJob(
        id=job_id,
        name=name,
        job_type=job_type,
        schedule=schedule,
        schedule_type=schedule_type,
        params=params,
        enabled=enabled,
        created_at=created_at,
    )

    # Save to database
    with get_db() as conn:
        conn.execute("""
            INSERT INTO scheduled_jobs (id, name, job_type, schedule, schedule_type, params, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (job.id, job.name, job.job_type, job.schedule, job.schedule_type,
              json.dumps(job.params), int(job.enabled), job.created_at))

    # Add to scheduler if enabled
    if enabled:
        scheduler = get_scheduler()
        if scheduler._running:
            scheduler._add_job_to_scheduler(job)

    logger.info(f"Created job: {name} ({job_id})")
    return job


async def update_job(
    job_id: str,
    name: str = None,
    schedule: str = None,
    schedule_type: str = None,
    params: dict = None,
    enabled: bool = None,
) -> Optional[ScheduledJob]:
    """Update an existing scheduled job."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        if not row:
            return None

        # Build update
        updates = []
        values = []

        if name is not None:
            updates.append("name = ?")
            values.append(name)
        if schedule is not None:
            updates.append("schedule = ?")
            values.append(schedule)
        if schedule_type is not None:
            updates.append("schedule_type = ?")
            values.append(schedule_type)
        if params is not None:
            updates.append("params = ?")
            values.append(json.dumps(params))
        if enabled is not None:
            updates.append("enabled = ?")
            values.append(int(enabled))

        if updates:
            values.append(job_id)
            conn.execute(
                f"UPDATE scheduled_jobs SET {', '.join(updates)} WHERE id = ?",  # nosec B608
                values
            )

        # Get updated job
        cursor = conn.execute("SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()

    job = ScheduledJob(
        id=row["id"],
        name=row["name"],
        job_type=row["job_type"],
        schedule=row["schedule"],
        schedule_type=row["schedule_type"],
        params=json.loads(row["params"]),
        enabled=bool(row["enabled"]),
        created_at=row["created_at"],
        last_run=row["last_run"],
        last_status=row["last_status"],
        last_result=row["last_result"],
        run_count=row["run_count"],
        error_count=row["error_count"],
    )

    # Update scheduler
    scheduler = get_scheduler()
    if scheduler._running:
        try:
            scheduler.scheduler.remove_job(job_id)
        except Exception:
            pass
        if job.enabled:
            scheduler._add_job_to_scheduler(job)

    logger.info(f"Updated job: {job.name} ({job_id})")
    return job


async def delete_job(job_id: str) -> bool:
    """Delete a scheduled job."""
    with get_db() as conn:
        cursor = conn.execute("SELECT name FROM scheduled_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        if not row:
            return False

        conn.execute("DELETE FROM scheduled_jobs WHERE id = ?", (job_id,))
        conn.execute("DELETE FROM job_history WHERE job_id = ?", (job_id,))

    # Remove from scheduler
    scheduler = get_scheduler()
    if scheduler._running:
        try:
            scheduler.scheduler.remove_job(job_id)
        except Exception:
            pass

    logger.info(f"Deleted job: {row['name']} ({job_id})")
    return True


async def get_job(job_id: str) -> Optional[ScheduledJob]:
    """Get a job by ID."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM scheduled_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        if not row:
            return None

    return ScheduledJob(
        id=row["id"],
        name=row["name"],
        job_type=row["job_type"],
        schedule=row["schedule"],
        schedule_type=row["schedule_type"],
        params=json.loads(row["params"]),
        enabled=bool(row["enabled"]),
        created_at=row["created_at"],
        last_run=row["last_run"],
        last_status=row["last_status"],
        last_result=row["last_result"],
        run_count=row["run_count"],
        error_count=row["error_count"],
    )


async def list_jobs(enabled_only: bool = False) -> list[ScheduledJob]:
    """List all scheduled jobs."""
    with get_db() as conn:
        if enabled_only:
            cursor = conn.execute("SELECT * FROM scheduled_jobs WHERE enabled = 1 ORDER BY created_at")
        else:
            cursor = conn.execute("SELECT * FROM scheduled_jobs ORDER BY created_at")

        jobs = []
        for row in cursor.fetchall():
            jobs.append(ScheduledJob(
                id=row["id"],
                name=row["name"],
                job_type=row["job_type"],
                schedule=row["schedule"],
                schedule_type=row["schedule_type"],
                params=json.loads(row["params"]),
                enabled=bool(row["enabled"]),
                created_at=row["created_at"],
                last_run=row["last_run"],
                last_status=row["last_status"],
                last_result=row["last_result"],
                run_count=row["run_count"],
                error_count=row["error_count"],
            ))
    return jobs


async def run_job_now(job_id: str) -> dict:
    """Manually trigger a job to run immediately."""
    job = await get_job(job_id)
    if not job:
        return {"error": f"Job not found: {job_id}"}

    scheduler = get_scheduler()
    if scheduler._running:
        # Trigger immediate execution
        await scheduler._execute_job(job_id)
        return {"success": True, "message": f"Job '{job.name}' executed"}
    else:
        return {"error": "Scheduler not running"}


async def get_job_history(job_id: str, limit: int = 20) -> list[dict]:
    """Get execution history for a job."""
    with get_db() as conn:
        cursor = conn.execute("""
            SELECT * FROM job_history
            WHERE job_id = ?
            ORDER BY started_at DESC
            LIMIT ?
        """, (job_id, limit))

        return [dict(row) for row in cursor.fetchall()]


async def get_supported_job_types() -> list[dict]:
    """Get list of supported job types with descriptions."""
    return [
        {"type": "health_check", "description": "Health check a single device", "params": ["device_name"]},
        {"type": "health_check_all", "description": "Health check all devices", "params": []},
        {"type": "backup_config", "description": "Backup device configuration", "params": ["device_name", "label"]},
        {"type": "backup_all", "description": "Backup all device configurations", "params": ["label"]},
        {"type": "compliance_check", "description": "Check config against golden template", "params": ["device_name", "template"]},
        {"type": "send_command", "description": "Send command to device", "params": ["device_name", "command"]},
        {"type": "bulk_command", "description": "Send command to multiple devices", "params": ["command", "devices"]},
        {"type": "lldp_discovery", "description": "Run LLDP topology discovery", "params": []},
        {"type": "snmp_poll", "description": "Poll device(s) via SNMP", "params": ["device_name"]},
        {"type": "daily_report", "description": "Generate agent daily operational report", "params": []},
    ]
