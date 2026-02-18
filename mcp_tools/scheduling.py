"""
Scheduling MCP tools.

This module provides tools for managing scheduled jobs:
- schedule_create: Create a new scheduled job
- schedule_list: List all scheduled jobs
- schedule_get: Get details of a specific job
- schedule_update: Update an existing job
- schedule_delete: Delete a scheduled job
- schedule_run_now: Trigger job to run immediately
- schedule_history: Get execution history
- schedule_job_types: List supported job types
"""

import json

from core.scheduler import (
    create_job,
    update_job,
    delete_job,
    get_job,
    list_jobs,
    run_job_now,
    get_job_history,
    get_supported_job_types,
)


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def schedule_create(
    name: str,
    job_type: str,
    schedule: str,
    schedule_type: str = "cron",
    params: str = None,
    enabled: bool = True
) -> str:
    """
    Create a new scheduled job.

    Args:
        name: Human-readable job name (e.g., "Daily Health Check")
        job_type: Type of job to run. Options:
            - health_check: Check single device (requires params.device_name)
            - health_check_all: Check all devices
            - backup_config: Backup device config (requires params.device_name)
            - backup_all: Backup all devices
            - compliance_check: Golden config check (requires params.device_name)
            - send_command: Run command (requires params.device_name, params.command)
            - bulk_command: Run command on multiple devices (requires params.command)
            - lldp_discovery: Run LLDP topology discovery
            - snmp_poll: Poll via SNMP (optional params.device_name)
        schedule: Cron expression ("0 6 * * *") or interval ("5m", "1h", "300s")
        schedule_type: "cron" (default) or "interval"
        params: JSON string with job parameters, e.g., '{"device_name": "R1"}'
        enabled: Start job immediately (default: true)

    Returns:
        JSON with created job details

    Examples:
        # Daily health check at 6 AM
        schedule_create("Daily Health Check", "health_check_all", "0 6 * * *")

        # Backup R1 every hour
        schedule_create("Hourly R1 Backup", "backup_config", "1h", "interval", '{"device_name": "R1"}')

        # Check compliance every day at midnight
        schedule_create("Nightly Compliance", "compliance_check", "0 0 * * *", params='{"device_name": "R1", "template": "security"}')
    """
    parsed_params = json.loads(params) if params else {}

    job = await create_job(
        name=name,
        job_type=job_type,
        schedule=schedule,
        schedule_type=schedule_type,
        params=parsed_params,
        enabled=enabled,
    )

    return json.dumps({
        "success": True,
        "message": f"Job '{name}' created",
        "job": job.to_dict()
    }, indent=2)


async def schedule_list(enabled_only: bool = False) -> str:
    """
    List all scheduled jobs.

    Args:
        enabled_only: If true, only show enabled jobs

    Returns:
        JSON with list of all scheduled jobs
    """
    jobs = await list_jobs(enabled_only=enabled_only)

    return json.dumps({
        "total": len(jobs),
        "enabled": sum(1 for j in jobs if j.enabled),
        "jobs": [j.to_dict() for j in jobs]
    }, indent=2)


async def schedule_get(job_id: str) -> str:
    """
    Get details of a specific scheduled job.

    Args:
        job_id: The job ID (8-character string)

    Returns:
        JSON with job details including last run status and history summary
    """
    job = await get_job(job_id)
    if not job:
        return json.dumps({"error": f"Job not found: {job_id}"})

    # Get recent history
    history = await get_job_history(job_id, limit=5)

    return json.dumps({
        "job": job.to_dict(),
        "recent_history": history
    }, indent=2)


async def schedule_update(
    job_id: str,
    name: str = None,
    schedule: str = None,
    schedule_type: str = None,
    params: str = None,
    enabled: bool = None
) -> str:
    """
    Update an existing scheduled job.

    Args:
        job_id: The job ID to update
        name: New job name (optional)
        schedule: New schedule expression (optional)
        schedule_type: "cron" or "interval" (optional)
        params: New job parameters as JSON string (optional)
        enabled: Enable/disable the job (optional)

    Returns:
        JSON with updated job details
    """
    parsed_params = json.loads(params) if params else None

    job = await update_job(
        job_id=job_id,
        name=name,
        schedule=schedule,
        schedule_type=schedule_type,
        params=parsed_params,
        enabled=enabled,
    )

    if not job:
        return json.dumps({"error": f"Job not found: {job_id}"})

    return json.dumps({
        "success": True,
        "message": f"Job '{job.name}' updated",
        "job": job.to_dict()
    }, indent=2)


async def schedule_delete(job_id: str) -> str:
    """
    Delete a scheduled job.

    Args:
        job_id: The job ID to delete

    Returns:
        JSON with deletion status
    """
    deleted = await delete_job(job_id)

    if not deleted:
        return json.dumps({"error": f"Job not found: {job_id}"})

    return json.dumps({
        "success": True,
        "message": f"Job {job_id} deleted"
    }, indent=2)


async def schedule_run_now(job_id: str) -> str:
    """
    Trigger a scheduled job to run immediately.

    The job will execute asynchronously and its result will be recorded
    in the job history.

    Args:
        job_id: The job ID to run

    Returns:
        JSON with execution status
    """
    result = await run_job_now(job_id)
    return json.dumps(result, indent=2)


async def schedule_history(job_id: str, limit: int = 20) -> str:
    """
    Get execution history for a scheduled job.

    Args:
        job_id: The job ID
        limit: Maximum number of history entries (default: 20)

    Returns:
        JSON with execution history (started_at, status, duration, result/error)
    """
    job = await get_job(job_id)
    if not job:
        return json.dumps({"error": f"Job not found: {job_id}"})

    history = await get_job_history(job_id, limit=limit)

    return json.dumps({
        "job_id": job_id,
        "job_name": job.name,
        "total_runs": job.run_count,
        "error_count": job.error_count,
        "history": history
    }, indent=2)


async def schedule_job_types() -> str:
    """
    Get list of supported job types with descriptions and required parameters.

    Returns:
        JSON with all supported job types and their configuration options
    """
    job_types = await get_supported_job_types()
    return json.dumps({
        "job_types": job_types,
        "schedule_types": [
            {"type": "cron", "description": "Cron expression (e.g., '0 6 * * *' = 6 AM daily)", "examples": [
                "0 * * * *     - Every hour",
                "0 6 * * *     - Daily at 6 AM",
                "0 0 * * 0     - Weekly on Sunday",
                "0 0 1 * *     - Monthly on the 1st",
                "*/5 * * * *   - Every 5 minutes",
            ]},
            {"type": "interval", "description": "Interval in seconds, minutes, hours, or days", "examples": [
                "300           - Every 300 seconds (5 min)",
                "5m            - Every 5 minutes",
                "1h            - Every hour",
                "24h           - Every 24 hours",
            ]},
        ]
    }, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": schedule_create, "name": "schedule_create", "category": "scheduling"},
    {"fn": schedule_list, "name": "schedule_list", "category": "scheduling"},
    {"fn": schedule_get, "name": "schedule_get", "category": "scheduling"},
    {"fn": schedule_update, "name": "schedule_update", "category": "scheduling"},
    {"fn": schedule_delete, "name": "schedule_delete", "category": "scheduling"},
    {"fn": schedule_run_now, "name": "schedule_run_now", "category": "scheduling"},
    {"fn": schedule_history, "name": "schedule_history", "category": "scheduling"},
    {"fn": schedule_job_types, "name": "schedule_job_types", "category": "scheduling"},
]
