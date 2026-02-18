"""
Async utilities for running coroutines in sync contexts.

Consolidates event loop management previously duplicated in:
- rag/query.py
- rag/ingest.py
- rag/network_tools.py

Usage:
    from core.async_utils import run_sync

    # Run an async function synchronously
    result = run_sync(my_async_function(arg1, arg2))

    # Or with a coroutine
    async def fetch_data():
        ...
    data = run_sync(fetch_data())
"""

import asyncio
from typing import Any, Coroutine, TypeVar

T = TypeVar("T")


def run_sync(coro: Coroutine[Any, Any, T]) -> T:
    """
    Run an async coroutine synchronously.

    Creates a new event loop, runs the coroutine to completion,
    and properly closes the loop.

    Args:
        coro: The coroutine to execute

    Returns:
        The result of the coroutine

    Example:
        async def async_add(a, b):
            return a + b

        result = run_sync(async_add(1, 2))  # Returns 3
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def try_create_task(coro: Coroutine[Any, Any, T]) -> bool:
    """
    Try to schedule an async task in the current event loop.

    If there's no running event loop, returns False without error.
    Useful for fire-and-forget background tasks.

    Args:
        coro: The coroutine to schedule

    Returns:
        True if task was scheduled, False if no event loop available
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
        return True
    except RuntimeError:
        # No event loop running - that's okay
        return False
