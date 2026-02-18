"""
Security package for MCP auth, RBAC, and command filtering.

Provides JWT validation, permission enforcement, and command policy
for the MCP tool layer, reusing the existing dashboard/auth system.
"""

from .command_policy import (
    BLOCKED_COMMANDS,
    BLOCKED_SHELL_CHARS,
    OPERATOR_ALLOWED_PREFIXES,
    validate_command,
)
from .tool_permissions import (
    TOOL_PERMISSIONS,
    COMMAND_VALIDATED_TOOLS,
    get_required_permission,
)
from .token_validator import validate_token
from .tool_auth import (
    MCP_AUTH_ENABLED,
    AuthContext,
    get_auth_context,
    set_auth_context,
    set_auth_from_token,
    clear_auth_context,
)
from .tool_wrapper import auth_enforced

__all__ = [
    "BLOCKED_COMMANDS",
    "BLOCKED_SHELL_CHARS",
    "OPERATOR_ALLOWED_PREFIXES",
    "validate_command",
    "TOOL_PERMISSIONS",
    "COMMAND_VALIDATED_TOOLS",
    "get_required_permission",
    "validate_token",
    "MCP_AUTH_ENABLED",
    "AuthContext",
    "get_auth_context",
    "set_auth_context",
    "set_auth_from_token",
    "clear_auth_context",
    "auth_enforced",
]
