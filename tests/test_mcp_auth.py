"""
Tests for MCP auth layer: JWT validation, RBAC, command filtering, context isolation.

All tests mock JWT decode and device connections -- no live devices needed.
"""

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import jwt
import pytest

# Shared test secret
TEST_SECRET = "test-secret-key"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token(
    username="testuser",
    role="operator",
    permissions=None,
    expired=False,
    jti="test-jti-001",
):
    """Create a signed JWT for testing."""
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": username,
        "role": role,
        "permissions": permissions or [],
        "jti": jti,
        "type": "access",
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, TEST_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# command_policy tests
# ---------------------------------------------------------------------------

class TestCommandPolicy:
    """Tests for security.command_policy."""

    def test_blocked_reload(self):
        from security.command_policy import validate_command

        valid, error = validate_command("reload", ["run_config_commands"])
        assert not valid
        assert "blocked" in error.lower()

    def test_blocked_write_erase(self):
        from security.command_policy import validate_command

        valid, error = validate_command("write erase", ["run_config_commands"])
        assert not valid
        assert "blocked" in error.lower()

    def test_blocked_shell_injection(self):
        from security.command_policy import validate_command

        valid, error = validate_command("show ip route; rm -rf /", ["run_show_commands"])
        assert not valid
        assert "blocked character" in error.lower()

    def test_show_allowed_with_permission(self):
        from security.command_policy import validate_command

        valid, error = validate_command("show ip route", ["run_show_commands"])
        assert valid
        assert error is None

    def test_show_denied_without_permission(self):
        from security.command_policy import validate_command

        valid, error = validate_command("show ip route", [])
        assert not valid
        assert "run_show_commands" in error

    def test_config_allowed_with_permission(self):
        from security.command_policy import validate_command

        valid, error = validate_command(
            "interface GigabitEthernet1", ["run_config_commands"]
        )
        assert valid
        assert error is None

    def test_config_denied_without_permission(self):
        from security.command_policy import validate_command

        valid, error = validate_command("interface GigabitEthernet1", ["run_show_commands"])
        assert not valid
        assert "run_config_commands" in error

    def test_multiline_per_line_validation(self):
        from security.command_policy import validate_multiline_commands

        commands = "interface Gi1\nreload\nno shutdown"
        valid, error = validate_multiline_commands(
            commands, ["run_config_commands"]
        )
        assert not valid
        assert "reload" in error.lower()

    def test_multiline_skips_comments_and_blanks(self):
        from security.command_policy import validate_multiline_commands

        commands = "! This is a comment\n\nshow ip route"
        valid, error = validate_multiline_commands(commands, ["run_show_commands"])
        assert valid

    def test_command_too_long(self):
        from security.command_policy import validate_command

        long_cmd = "show " + "x" * 1000
        valid, error = validate_command(long_cmd, ["run_show_commands"])
        assert not valid
        assert "length" in error.lower()

    def test_operator_prefix_show(self):
        """show version allowed with run_show_commands (operator role)."""
        from security.command_policy import validate_command

        valid, error = validate_command("show version", ["run_show_commands"])
        assert valid
        assert error is None


# ---------------------------------------------------------------------------
# token_validator tests
# ---------------------------------------------------------------------------

class TestTokenValidator:
    """Tests for security.token_validator."""

    @patch("security.token_validator.JWT_SECRET", TEST_SECRET)
    @patch("security.token_validator.JWT_ALGORITHM", "HS256")
    def test_valid_token(self):
        from security.token_validator import validate_token

        token = _make_token(permissions=["run_show_commands"])
        # Mock blacklist check to not be blacklisted
        with patch("dashboard.auth.tokens.is_token_blacklisted", return_value=False):
            result = validate_token(token)
        assert result is not None
        assert result["sub"] == "testuser"
        assert "run_show_commands" in result["permissions"]

    @patch("security.token_validator.JWT_SECRET", TEST_SECRET)
    @patch("security.token_validator.JWT_ALGORITHM", "HS256")
    def test_expired_token(self):
        from security.token_validator import validate_token

        token = _make_token(expired=True)
        result = validate_token(token)
        assert result is None

    @patch("security.token_validator.JWT_SECRET", "wrong-secret")
    @patch("security.token_validator.JWT_ALGORITHM", "HS256")
    def test_invalid_signature(self):
        from security.token_validator import validate_token

        token = _make_token()
        result = validate_token(token)
        assert result is None

    @patch("security.token_validator.JWT_SECRET", TEST_SECRET)
    @patch("security.token_validator.JWT_ALGORITHM", "HS256")
    def test_blacklisted_token(self):
        from security.token_validator import validate_token

        token = _make_token()
        with patch("dashboard.auth.tokens.is_token_blacklisted", return_value=True):
            result = validate_token(token)
        assert result is None


# ---------------------------------------------------------------------------
# tool_auth (context vars) tests
# ---------------------------------------------------------------------------

class TestToolAuth:
    """Tests for security.tool_auth AuthContext and context vars."""

    def test_default_anonymous(self):
        from security.tool_auth import get_auth_context

        ctx = get_auth_context()
        assert ctx.username == "anonymous"
        assert not ctx.is_authenticated
        assert ctx.permissions == []

    def test_set_from_token(self):
        from security.tool_auth import set_auth_from_token, get_auth_context, clear_auth_context

        payload = {
            "sub": "admin",
            "role": "admin",
            "permissions": ["run_show_commands", "run_config_commands"],
            "jti": "abc-123",
        }
        ctx = set_auth_from_token(payload)
        assert ctx.username == "admin"
        assert ctx.is_authenticated
        assert "run_config_commands" in ctx.permissions

        # Verify get returns same
        assert get_auth_context().username == "admin"

        # Clean up
        clear_auth_context()
        assert get_auth_context().username == "anonymous"

    def test_context_isolation(self):
        """Concurrent async tasks should have independent auth contexts."""
        from security.tool_auth import set_auth_context, get_auth_context, AuthContext, clear_auth_context

        results = {}

        async def task_a():
            set_auth_context(AuthContext(username="user_a", permissions=["perm_a"]))
            await asyncio.sleep(0.01)  # Yield to let task_b run
            results["a"] = get_auth_context().username

        async def task_b():
            set_auth_context(AuthContext(username="user_b", permissions=["perm_b"]))
            await asyncio.sleep(0.01)
            results["b"] = get_auth_context().username

        async def run():
            await asyncio.gather(
                asyncio.create_task(task_a()),
                asyncio.create_task(task_b()),
            )

        asyncio.run(run())

        # Each task should see its own context
        assert results["a"] == "user_a"
        assert results["b"] == "user_b"

        # Clean up main context
        clear_auth_context()


# ---------------------------------------------------------------------------
# tool_wrapper tests
# ---------------------------------------------------------------------------

class TestToolWrapper:
    """Tests for security.tool_wrapper.auth_enforced."""

    def test_auth_disabled_passes_through(self):
        """When MCP_AUTH_ENABLED=false, auth_enforced returns the original function."""
        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", False):
            from security.tool_wrapper import auth_enforced

            def my_tool():
                return "ok"

            wrapped = auth_enforced("my_tool", my_tool)
            assert wrapped is my_tool

    def test_permission_denied_send_config(self):
        """send_config requires run_config_commands -- operator without it is denied."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            async def send_config(device_name: str, commands: str):
                return "configured"

            wrapped = auth_enforced("send_config", send_config)

            # Set context: operator without run_config_commands
            set_auth_context(AuthContext(
                username="operator1",
                role="operator",
                permissions=["run_show_commands"],
            ))

            result = asyncio.run(wrapped("R1", "interface Gi1"))
            assert "Permission denied" in result
            clear_auth_context()

    def test_permission_granted_send_config(self):
        """send_config with run_config_commands permission passes through."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            async def send_config(device_name: str, commands: str):
                return "configured"

            wrapped = auth_enforced("send_config", send_config)

            set_auth_context(AuthContext(
                username="engineer1",
                role="engineer",
                permissions=["run_show_commands", "run_config_commands"],
            ))

            result = asyncio.run(wrapped("R1", "interface Gi1"))
            assert result == "configured"
            clear_auth_context()

    def test_command_blocked_reload(self):
        """send_command with 'reload' should be rejected by command validation."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            async def send_command(device_name: str, command: str):
                return "output"

            wrapped = auth_enforced("send_command", send_command)

            set_auth_context(AuthContext(
                username="admin1",
                role="admin",
                permissions=["run_show_commands", "run_config_commands"],
            ))

            result = asyncio.run(wrapped("R1", "reload"))
            assert "blocked" in result.lower()
            clear_auth_context()

    def test_command_allowed_show_ip_route(self):
        """send_command with 'show ip route' passes through."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            async def send_command(device_name: str, command: str):
                return "routing table output"

            wrapped = auth_enforced("send_command", send_command)

            set_auth_context(AuthContext(
                username="operator1",
                role="operator",
                permissions=["run_show_commands"],
            ))

            result = asyncio.run(wrapped("R1", "show ip route"))
            assert result == "routing table output"
            clear_auth_context()

    def test_multiline_config_per_line_validation(self):
        """Multi-line config with a dangerous line in the middle is caught."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            async def send_config(device_name: str, commands: str):
                return "configured"

            wrapped = auth_enforced("send_config", send_config)

            set_auth_context(AuthContext(
                username="engineer1",
                role="engineer",
                permissions=["run_config_commands"],
            ))

            commands = "interface Gi1\nreload\nno shutdown"
            result = asyncio.run(wrapped("R1", commands))
            assert "reload" in result.lower()
            assert "blocked" in result.lower()
            clear_auth_context()

    def test_sync_wrapper(self):
        """Sync functions are also wrapped correctly."""
        from security.tool_auth import set_auth_context, AuthContext, clear_auth_context

        with patch("security.tool_wrapper.MCP_AUTH_ENABLED", True):
            from security.tool_wrapper import auth_enforced

            def get_devices():
                return ["R1", "R2"]

            wrapped = auth_enforced("get_devices", get_devices)

            # get_devices is public (no permission required)
            set_auth_context(AuthContext(username="anyone"))
            result = wrapped()
            assert result == ["R1", "R2"]
            clear_auth_context()


# ---------------------------------------------------------------------------
# tool_permissions tests
# ---------------------------------------------------------------------------

class TestToolPermissions:
    """Tests for security.tool_permissions."""

    def test_send_config_requires_config_permission(self):
        from security.tool_permissions import get_required_permission

        assert get_required_permission("send_config") == "run_config_commands"

    def test_get_devices_is_public(self):
        from security.tool_permissions import get_required_permission

        assert get_required_permission("get_devices") is None

    def test_unknown_tool_is_public(self):
        from security.tool_permissions import get_required_permission

        assert get_required_permission("nonexistent_tool") is None

    def test_remediate_interface_requires_permission(self):
        from security.tool_permissions import get_required_permission

        assert get_required_permission("remediate_interface") == "remediate_interfaces"

    def test_command_validated_tools(self):
        from security.tool_permissions import COMMAND_VALIDATED_TOOLS

        assert "send_command" in COMMAND_VALIDATED_TOOLS
        assert "send_config" in COMMAND_VALIDATED_TOOLS
        assert "bulk_command" in COMMAND_VALIDATED_TOOLS
        assert "get_devices" not in COMMAND_VALIDATED_TOOLS


# ---------------------------------------------------------------------------
# HTTP proxy auth tests
# ---------------------------------------------------------------------------

class TestProxyAuth:
    """Tests for mcp_http_proxy auth middleware."""

    def test_proxy_invalid_token_returns_401(self):
        """HTTP proxy rejects invalid Bearer token with 401."""
        with patch.dict(os.environ, {"MCP_AUTH_ENABLED": "true"}):
            # Need to reload modules to pick up env var change
            import importlib
            import security.tool_auth
            importlib.reload(security.tool_auth)

            # Temporarily set the flag directly for this test
            original = security.tool_auth.MCP_AUTH_ENABLED
            security.tool_auth.MCP_AUTH_ENABLED = True

            try:
                # Patch at the proxy module level
                with patch("security.token_validator.validate_token", return_value=None):
                    from mcp_http_proxy import app

                    # Patch the module-level flag the proxy imported
                    with patch("mcp_http_proxy.MCP_AUTH_ENABLED", True):
                        client = app.test_client()
                        response = client.post(
                            "/tools/get_devices",
                            headers={"Authorization": "Bearer invalid-token"},
                            content_type="application/json",
                        )
                        assert response.status_code == 401
            finally:
                security.tool_auth.MCP_AUTH_ENABLED = original

    def test_proxy_health_exempt(self):
        """Health endpoint is accessible without auth even when auth is enabled."""
        with patch("mcp_http_proxy.MCP_AUTH_ENABLED", True):
            from mcp_http_proxy import app

            client = app.test_client()
            response = client.get("/health")
            assert response.status_code == 200


# ---------------------------------------------------------------------------
# Event logger user param test
# ---------------------------------------------------------------------------

class TestEventLoggerUser:
    """Test that event logger accepts and records user param."""

    def test_log_event_with_user(self):
        from core.event_logger import EventLogger

        logger = EventLogger(max_events=10)
        logger._loaded = True  # Skip file load

        event = logger.log(
            action="auth_denied",
            details="test denial",
            status="forbidden",
            user="testuser",
        )
        assert event["user"] == "testuser"
        assert event["action"] == "auth_denied"

    def test_log_event_without_user(self):
        from core.event_logger import EventLogger

        logger = EventLogger(max_events=10)
        logger._loaded = True

        event = logger.log(action="health_check", status="success")
        assert "user" not in event
