"""
Auth context management for MCP tool calls.

Uses ``contextvars`` to carry auth state through async tool invocations
without modifying tool function signatures.

Scope limitations of ``contextvars``:
- Values propagate within the same event loop and into child
  ``asyncio.Task`` instances automatically.
- Values do NOT propagate into ``asyncio.to_thread()`` threadpools or
  subprocesses. If a future tool needs auth inside a threadpool, copy the
  context manually with ``contextvars.copy_context().run(...)``.
- The existing ``_netconf_health_check_sync`` in ``mcp_tools/device.py``
  uses ``asyncio.to_thread()`` but health checks are public, so this is
  not an issue today.
"""

import os
from contextvars import ContextVar
from dataclasses import dataclass, field


# Feature flag -- controls whether auth enforcement is active.
# Default: enabled. Set MCP_AUTH_ENABLED=false to disable for local dev.
MCP_AUTH_ENABLED: bool = os.getenv("MCP_AUTH_ENABLED", "true").lower() == "true"


@dataclass(frozen=True)
class AuthContext:
    """Immutable auth state for the current request / tool call."""

    username: str = "anonymous"
    role: str = "none"
    permissions: list[str] = field(default_factory=list)
    token_jti: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.username != "anonymous"


# Default: anonymous (no permissions)
_auth_context: ContextVar[AuthContext] = ContextVar(
    "mcp_auth_context", default=AuthContext()
)


def get_auth_context() -> AuthContext:
    """Return the ``AuthContext`` for the current async task."""
    return _auth_context.get()


def set_auth_context(ctx: AuthContext) -> None:
    """Set the ``AuthContext`` for the current async task."""
    _auth_context.set(ctx)


def set_auth_from_token(payload: dict) -> AuthContext:
    """Build an ``AuthContext`` from a decoded JWT payload and set it.

    Args:
        payload: Decoded JWT dict with keys ``sub``, ``role``,
                 ``permissions``, ``jti``.

    Returns:
        The newly created ``AuthContext``.
    """
    ctx = AuthContext(
        username=payload.get("sub", "unknown"),
        role=payload.get("role", "none"),
        permissions=payload.get("permissions", []),
        token_jti=payload.get("jti"),
    )
    _auth_context.set(ctx)
    return ctx


def clear_auth_context() -> None:
    """Reset auth context to the anonymous default."""
    _auth_context.set(AuthContext())
