"""
Auth enforcement wrapper for MCP tool functions.

``auth_enforced(tool_name, fn)`` returns a wrapper that:
1. Checks the tool-level permission from ``tool_permissions.py``
2. For command-validated tools, inspects the ``command`` / ``commands``
   argument against the command policy
3. Logs denials via the event logger

When ``MCP_AUTH_ENABLED`` is ``false`` (opt-in for local dev), the
original function is returned unchanged (zero overhead at call time --
the check happens once at registration time).
"""

import asyncio
import functools
import inspect
import logging
from typing import Callable

from .tool_auth import MCP_AUTH_ENABLED, get_auth_context
from .tool_permissions import TOOL_PERMISSIONS, COMMAND_VALIDATED_TOOLS, get_required_permission
from .command_policy import validate_command, validate_multiline_commands

logger = logging.getLogger(__name__)


def _log_denial(tool_name: str, username: str, reason: str, details: str = "") -> None:
    """Log an auth denial through the event logger."""
    try:
        from core.event_logger import log_event

        log_event(
            action="auth_denied",
            details=f"tool={tool_name} user={username} reason={reason} {details}".strip(),
            status="forbidden",
            user=username,
        )
    except Exception:
        # Don't let logging failures break auth enforcement
        logger.warning("Failed to log auth denial for tool=%s user=%s", tool_name, username)


def _check_permission(tool_name: str) -> str | None:
    """Check tool-level permission. Returns error message or None."""
    required = get_required_permission(tool_name)
    if required is None:
        return None

    ctx = get_auth_context()
    if required in ctx.permissions:
        return None

    return f"Permission denied: '{tool_name}' requires '{required}' permission"


def _check_command_args(tool_name: str, args: tuple, kwargs: dict) -> str | None:
    """For command-validated tools, validate the command content.

    Returns error message or None.
    """
    if tool_name not in COMMAND_VALIDATED_TOOLS:
        return None

    ctx = get_auth_context()

    # Extract the command / commands argument
    command_value = kwargs.get("command") or kwargs.get("commands")
    if command_value is None:
        # Try positional -- send_command(device_name, command)
        # send_config(device_name, commands)
        if len(args) >= 2:
            command_value = args[1]

    if not command_value:
        return None  # No command to validate

    # Multi-line validation for send_config and bulk_command
    if tool_name in ("send_config", "bulk_command") and '\n' in str(command_value):
        valid, error = validate_multiline_commands(str(command_value), ctx.permissions)
    else:
        valid, error = validate_command(str(command_value), ctx.permissions)

    return error


def auth_enforced(tool_name: str, fn: Callable) -> Callable:
    """Wrap a tool function with auth enforcement.

    When ``MCP_AUTH_ENABLED`` is ``false``, returns ``fn`` unchanged.

    Args:
        tool_name: The registered MCP tool name (e.g. ``"send_command"``).
        fn: The original tool function (sync or async).

    Returns:
        Wrapped function with the same signature, or ``fn`` unchanged.
    """
    if not MCP_AUTH_ENABLED:
        return fn

    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            # Tool-level permission check
            perm_error = _check_permission(tool_name)
            if perm_error:
                ctx = get_auth_context()
                _log_denial(tool_name, ctx.username, perm_error)
                return perm_error

            # Command content validation
            cmd_error = _check_command_args(tool_name, args, kwargs)
            if cmd_error:
                ctx = get_auth_context()
                _log_denial(tool_name, ctx.username, cmd_error)
                return cmd_error

            return await fn(*args, **kwargs)

        return async_wrapper
    else:
        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            perm_error = _check_permission(tool_name)
            if perm_error:
                ctx = get_auth_context()
                _log_denial(tool_name, ctx.username, perm_error)
                return perm_error

            cmd_error = _check_command_args(tool_name, args, kwargs)
            if cmd_error:
                ctx = get_auth_context()
                _log_denial(tool_name, ctx.username, cmd_error)
                return cmd_error

            return fn(*args, **kwargs)

        return sync_wrapper
