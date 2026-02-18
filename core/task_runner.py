"""
Task runner with Celery fallback to synchronous execution.

Provides a wrapper that automatically falls back to sync execution
when the Celery broker (Redis) is unavailable. This ensures critical
tasks like health checks and provisioning still work during Redis outages.
"""

import logging
import os
import time
from functools import wraps
from typing import Any, Callable, Optional, TypeVar
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Configuration
BROKER_CHECK_INTERVAL = int(os.getenv('BROKER_CHECK_INTERVAL', '30'))  # seconds
BROKER_CHECK_TIMEOUT = float(os.getenv('BROKER_CHECK_TIMEOUT', '2.0'))  # seconds

# Cache for broker status
_broker_status_cache: dict = {
    'available': None,
    'last_check': 0,
    'consecutive_failures': 0,
}


@dataclass
class TaskResult:
    """Result wrapper for both sync and async task execution."""
    success: bool
    result: Any
    task_id: Optional[str] = None
    is_async: bool = False
    error: Optional[str] = None

    def get(self, timeout: float = None) -> Any:
        """Get result (immediate for sync, wait for async)."""
        if not self.is_async or self.result is None:
            return self.result

        # For async tasks, wait for result
        try:
            return self.result.get(timeout=timeout)
        except Exception as e:
            logger.error(f"Failed to get async result: {e}")
            return None


def check_broker_availability(force: bool = False) -> bool:
    """
    Check if the Celery broker (Redis) is available.

    Uses cached result unless force=True or cache is stale.

    Returns:
        True if broker is available, False otherwise
    """
    global _broker_status_cache

    now = time.time()

    # Use cached result if recent (unless forced)
    if not force:
        cache_age = now - _broker_status_cache['last_check']
        if cache_age < BROKER_CHECK_INTERVAL and _broker_status_cache['available'] is not None:
            return _broker_status_cache['available']

    # Check Redis connectivity
    try:
        import redis
        broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
        client = redis.from_url(broker_url, socket_timeout=BROKER_CHECK_TIMEOUT)
        client.ping()

        _broker_status_cache['available'] = True
        _broker_status_cache['last_check'] = now
        _broker_status_cache['consecutive_failures'] = 0

        return True

    except Exception as e:
        _broker_status_cache['consecutive_failures'] += 1
        _broker_status_cache['available'] = False
        _broker_status_cache['last_check'] = now

        if _broker_status_cache['consecutive_failures'] <= 3:
            logger.warning(f"Celery broker unavailable: {e}")
        elif _broker_status_cache['consecutive_failures'] == 4:
            logger.error("Celery broker repeatedly unavailable - falling back to sync execution")

        return False


def run_task(
    task: Callable,
    *args,
    sync_fallback: bool = True,
    force_sync: bool = False,
    **kwargs
) -> TaskResult:
    """
    Run a Celery task with automatic fallback to sync execution.

    Args:
        task: The Celery task to run (must be a @shared_task or @celery.task)
        *args: Positional arguments for the task
        sync_fallback: If True, fall back to sync execution when broker unavailable
        force_sync: If True, always run synchronously (useful for testing)
        **kwargs: Keyword arguments for the task

    Returns:
        TaskResult containing success status and result/error

    Example:
        from core.tasks import health_check
        result = run_task(health_check, "R1")
        print(result.result)
    """
    # Force sync mode
    if force_sync:
        return _run_sync(task, *args, **kwargs)

    # Check broker availability
    if check_broker_availability():
        return _run_async(task, *args, **kwargs)

    # Fallback to sync
    if sync_fallback:
        logger.info(f"Falling back to sync execution for task {task.name}")
        return _run_sync(task, *args, **kwargs)

    # No fallback - return error
    return TaskResult(
        success=False,
        result=None,
        error="Celery broker unavailable and sync_fallback=False"
    )


def _run_async(task: Callable, *args, **kwargs) -> TaskResult:
    """Run task via Celery async."""
    try:
        async_result = task.delay(*args, **kwargs)
        return TaskResult(
            success=True,
            result=async_result,
            task_id=async_result.id,
            is_async=True
        )
    except Exception as e:
        logger.error(f"Failed to queue async task {task.name}: {e}")
        return TaskResult(
            success=False,
            result=None,
            error=str(e)
        )


def _run_sync(task: Callable, *args, **kwargs) -> TaskResult:
    """Run task synchronously (bypass Celery)."""
    try:
        # Celery tasks have a .run() method for direct execution
        if hasattr(task, 'run'):
            result = task.run(*args, **kwargs)
        else:
            # Fallback for plain functions
            result = task(*args, **kwargs)

        return TaskResult(
            success=True,
            result=result,
            is_async=False
        )
    except Exception as e:
        logger.error(f"Sync task execution failed for {getattr(task, 'name', task.__name__)}: {e}")
        return TaskResult(
            success=False,
            result=None,
            error=str(e)
        )


def with_sync_fallback(sync_fallback: bool = True):
    """
    Decorator to wrap Celery tasks with sync fallback capability.

    Usage:
        @with_sync_fallback()
        @shared_task
        def my_task(arg):
            ...

        # Run with fallback
        my_task.run_with_fallback(arg)
    """
    def decorator(task_func):
        @wraps(task_func)
        def wrapper(*args, **kwargs):
            return run_task(task_func, *args, sync_fallback=sync_fallback, **kwargs)

        # Attach fallback runner
        if hasattr(task_func, 'delay'):
            task_func.run_with_fallback = lambda *a, **kw: run_task(
                task_func, *a, sync_fallback=sync_fallback, **kw
            )
        return task_func

    return decorator


def get_broker_status() -> dict:
    """
    Get current broker status information.

    Returns:
        Dict with availability status and diagnostics
    """
    available = check_broker_availability(force=True)

    return {
        'available': available,
        'consecutive_failures': _broker_status_cache['consecutive_failures'],
        'last_check': _broker_status_cache['last_check'],
        'check_interval_seconds': BROKER_CHECK_INTERVAL,
        'mode': 'async' if available else 'sync_fallback'
    }
