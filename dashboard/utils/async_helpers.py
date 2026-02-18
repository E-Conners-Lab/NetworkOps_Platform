"""Shared async-to-sync helpers for Flask route handlers."""

import asyncio
import contextvars


def run_async(coro):
    """Run an async coroutine in a sync context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def run_async_with_context(coro):
    """Run an async coroutine preserving contextvars (for auth propagation)."""
    ctx = contextvars.copy_context()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return ctx.run(loop.run_until_complete, coro)
    finally:
        loop.close()
