"""
Shared concurrency and device interaction utilities for MCP tools.

This module provides:
- Connection throttling via semaphore
- Memory recording callback
- Common helper functions used across tool modules
"""
import asyncio
import os
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Any

if TYPE_CHECKING:
    from memory import MemoryStore

# =============================================================================
# Concurrency Control
# =============================================================================
# Limit concurrent device connections to avoid overwhelming network/devices
# With Redis caching reducing actual device queries, we can safely increase this
# Default: 100 - scale testing showed optimal throughput at 100 concurrent (278 devices/sec)
# Real bottleneck is device VTY lines (5-16), not this limit
MAX_CONCURRENT_CONNECTIONS = int(os.getenv("MAX_CONCURRENT_CONNECTIONS", "100"))
_connection_semaphore: asyncio.Semaphore | None = None


def get_semaphore() -> asyncio.Semaphore:
    """Get or create the connection semaphore (must be called within async context)."""
    global _connection_semaphore
    if _connection_semaphore is None:
        _connection_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    return _connection_semaphore


def reset_semaphore():
    """Reset the semaphore (useful for testing)."""
    global _connection_semaphore
    _connection_semaphore = None


async def throttled(coro):
    """Execute a coroutine with semaphore-based throttling."""
    sem = get_semaphore()
    async with sem:
        return await coro


def throttled_decorator(func: Callable) -> Callable:
    """
    Decorator to ensure limited concurrent execution of async functions.

    Usage:
        @throttled_decorator
        async def my_function():
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        async with get_semaphore():
            return await func(*args, **kwargs)
    return wrapper


# =============================================================================
# Memory Recording
# =============================================================================
_memory_store: "MemoryStore | None" = None


def set_memory_store(store: "MemoryStore"):
    """Set the global memory store for recording tool calls."""
    global _memory_store
    _memory_store = store


def get_memory_store() -> "MemoryStore | None":
    """Get the global memory store."""
    return _memory_store


async def record_to_memory(action: str, device: str, details: str, status: str):
    """
    Background task to record event to memory system.

    This is a non-blocking operation that won't fail the calling tool.
    """
    try:
        if _memory_store is not None:
            await _memory_store.record_tool_call(
                tool_name=action,
                device_name=device,
                result_summary=details,
                status=status
            )
    except Exception:
        pass  # Don't fail on memory recording errors
