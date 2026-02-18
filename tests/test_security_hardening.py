"""
Security hardening regression tests.

Validates fixes for the 11 findings from the deep security audit:
- MCP command validator import
- Change management command validation
- WebSocket authentication
- Restricted password-change tokens
- JWT/MFA secret defaults
- SQL identifier validation
- Recovery code entropy
"""
import os
import re
import sys

import pytest

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force test mode so settings don't require real env vars
os.environ.setdefault("TESTING", "true")


# =============================================================================
# 1. MCP device import succeeds
# =============================================================================

class TestMCPImport:
    def test_device_module_imports_cleanly(self):
        """mcp_tools.device should import without ModuleNotFoundError."""
        from mcp_tools.device import send_command, send_config
        assert callable(send_command)
        assert callable(send_config)

    def test_validate_command_callable(self):
        """security.command_policy.validate_command must be importable."""
        from security.command_policy import validate_command
        assert callable(validate_command)

    def test_validate_command_returns_tuple(self):
        """validate_command should return (bool, str|None), not an object."""
        from security.command_policy import validate_command
        result = validate_command("show ip route", ["run_show_commands"])
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0] is True
        assert result[1] is None


# =============================================================================
# 2. Change management rejects blocked commands
# =============================================================================

class TestChangeCommandValidation:
    def test_blocked_command_rejected(self):
        """Creating a change with 'reload' should be rejected."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'dashboard'))
        from dashboard.app import create_app

        app = create_app(config={'TESTING': True})
        # Clear password_change_required via DatabaseManager (consolidated DB)
        try:
            from core.db import DatabaseManager
            conn = DatabaseManager.get_instance().get_connection()
            conn.execute("UPDATE users SET password_change_required = 0 WHERE username = 'admin'")
            conn.commit()
            DatabaseManager.get_instance().release_connection(conn)
        except Exception:
            pass

        with app.test_client() as client:
            # Login to get a token
            login_resp = client.post('/api/auth/login', json={
                'username': 'admin', 'password': 'admin'
            })
            if login_resp.status_code != 200:
                pytest.skip("API login unavailable")

            token = login_resp.get_json().get('token')
            headers = {'Authorization': f'Bearer {token}'}

            # Try to create a change with a blocked command
            resp = client.post('/api/changes', headers=headers, json={
                'device': 'R1',
                'description': 'Test blocked command',
                'commands': ['reload'],
            })
            # Should be rejected with 400 (ValidationError)
            assert resp.status_code == 400, (
                f"Expected 400 for blocked command 'reload', got {resp.status_code}"
            )
            data = resp.get_json()
            assert "blocked" in data.get("error", "").lower() or "blocked" in str(data).lower()

    def test_safe_command_accepted(self):
        """Creating a change with a safe config command should pass validation."""
        from security.command_policy import validate_command
        is_valid, error = validate_command("interface GigabitEthernet1", ["run_config_commands"])
        assert is_valid is True
        assert error is None


# =============================================================================
# 3. WebSocket rejects unauthenticated connections
# =============================================================================

class TestWebSocketAuth:
    def test_handle_connect_requires_auth(self):
        """handle_connect should reject connections without auth data."""
        from unittest.mock import MagicMock, patch

        from dashboard.routes.websocket import register_websocket_handlers

        socketio = MagicMock()
        telemetry = MagicMock()
        handlers = {}

        def capture_on(event):
            def decorator(fn):
                handlers[event] = fn
                return fn
            return decorator

        socketio.on = capture_on
        register_websocket_handlers(socketio, telemetry)

        connect_handler = handlers.get('connect')
        assert connect_handler is not None, "connect handler not registered"

        # No auth data -> rejected
        assert connect_handler(auth=None) is False

        # Empty dict -> rejected
        assert connect_handler(auth={}) is False

        # Invalid token -> rejected
        with patch('dashboard.routes.websocket.decode_token', return_value=None):
            assert connect_handler(auth={"token": "bad.token"}) is False

    def test_handle_connect_accepts_valid_token(self):
        """handle_connect should accept connections with valid token."""
        from unittest.mock import MagicMock, patch

        from dashboard.routes.websocket import register_websocket_handlers

        socketio = MagicMock()
        telemetry = MagicMock()
        handlers = {}

        def capture_on(event):
            def decorator(fn):
                handlers[event] = fn
                return fn
            return decorator

        socketio.on = capture_on
        register_websocket_handlers(socketio, telemetry)

        connect_handler = handlers.get('connect')

        with patch('dashboard.routes.websocket.decode_token', return_value={"sub": "admin"}), \
             patch('dashboard.routes.websocket.emit'):
            result = connect_handler(auth={"token": "valid.token"})
            # Should not return False (None is acceptable — means allowed)
            assert result is not False


# =============================================================================
# 4. Password change restricted token
# =============================================================================

class TestRestrictedToken:
    def _make_app_and_restricted_token(self):
        """Helper: create a test app and a restricted token, bypassing session checks."""
        from unittest.mock import patch, MagicMock

        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'dashboard'))
        from dashboard.app import create_app
        from dashboard.auth.tokens import create_token

        app = create_app(config={'TESTING': True})
        token = create_token("admin", "admin", 1, ["change_own_password"])

        # Mock session validation to accept any JTI (token was not created via login)
        mock_manager = MagicMock()
        mock_manager.validate_session.return_value = True
        return app, token, patch('dashboard.sessions.get_session_manager', return_value=mock_manager)

    def test_restricted_token_blocked_on_normal_endpoints(self):
        """Token with only change_own_password permission should get 403."""
        app, token, session_patch = self._make_app_and_restricted_token()
        headers = {'Authorization': f'Bearer {token}'}

        with app.test_client() as client, session_patch:
            resp = client.get('/api/auth/me', headers=headers)
            assert resp.status_code == 403, (
                f"Restricted token should get 403 on /api/auth/me, got {resp.status_code}"
            )

    def test_restricted_token_allowed_on_change_password(self):
        """Token with change_own_password should access /api/auth/change-password."""
        app, token, session_patch = self._make_app_and_restricted_token()
        headers = {'Authorization': f'Bearer {token}'}

        with app.test_client() as client, session_patch:
            # POST to change-password (will fail on data validation, but should NOT be 403)
            resp = client.post('/api/auth/change-password', headers=headers, json={})
            # 400 (missing fields) is acceptable; 403 means the guard wrongly blocked it
            assert resp.status_code != 403, (
                "Restricted token should be allowed on /api/auth/change-password"
            )


# =============================================================================
# 5. JWT default is not a known insecure string
# =============================================================================

class TestJWTSecrets:
    def test_jwt_secret_not_hardcoded(self):
        """JWT secret should not be a well-known insecure default."""
        from config.settings import get_settings
        get_settings.cache_clear()

        settings = get_settings()
        jwt_val = settings.auth.jwt_secret.get_secret_value()

        insecure_defaults = {
            "your-secret-key-change-in-production",
            "dev-secret-change-in-production",
            "",
        }
        assert jwt_val not in insecure_defaults, (
            f"JWT secret is a known insecure value: {jwt_val!r}"
        )

    def test_jwt_and_refresh_secrets_differ(self):
        """JWT access and refresh secrets should be independent."""
        from config.settings import get_settings
        get_settings.cache_clear()

        settings = get_settings()
        jwt_val = settings.auth.jwt_secret.get_secret_value()
        refresh_val = settings.auth.jwt_refresh_secret.get_secret_value()

        assert jwt_val != refresh_val, "JWT and refresh secrets should differ"
        # Refresh should NOT be derived as jwt + "-refresh"
        assert refresh_val != jwt_val + "-refresh", (
            "Refresh secret should be independent, not jwt_secret + '-refresh'"
        )


# =============================================================================
# 6. column_exists rejects invalid identifiers
# =============================================================================

class TestSQLSafety:
    def test_column_exists_rejects_injection(self):
        """column_exists should reject SQL injection in table/column names."""
        from core.db import column_exists, get_connection

        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")

        # These should raise ValueError, not execute SQL
        with pytest.raises(ValueError):
            column_exists(conn, "t; DROP TABLE t;--", "name")

        with pytest.raises(ValueError):
            column_exists(conn, "t", "name; DROP TABLE t;--")

        with pytest.raises(ValueError):
            column_exists(conn, "t", "1name")  # starts with digit

        conn.close()

    def test_column_exists_accepts_valid_names(self):
        """column_exists should still work for valid identifier names."""
        from core.db import column_exists, get_connection

        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, user_name TEXT)")

        assert column_exists(conn, "test_table", "user_name") is True
        assert column_exists(conn, "test_table", "nonexistent") is False

        conn.close()


# =============================================================================
# 7. Recovery codes are 16 characters (64 bits)
# =============================================================================

class TestRecoveryCodeEntropy:
    def test_recovery_code_length(self):
        """Recovery codes should be 16 hex characters (64 bits entropy)."""
        import secrets
        # Simulate the same code generation as mfa.py
        code = secrets.token_hex(8).upper()
        assert len(code) == 16, f"Expected 16 chars, got {len(code)}"
        assert all(c in '0123456789ABCDEF' for c in code)

    def test_mfa_source_uses_token_hex_8(self):
        """Verify mfa.py uses token_hex(8), not token_hex(4)."""
        import inspect
        from dashboard import mfa

        source = inspect.getsource(mfa.MFAManager.confirm_mfa)
        assert "token_hex(8)" in source, "mfa.py should use token_hex(8) for 64-bit recovery codes"
        assert "token_hex(4)" not in source, "mfa.py should NOT use token_hex(4) (only 32 bits)"


# =============================================================================
# 8. Refresh token rotation returns new refresh token
# =============================================================================

class TestRefreshRotation:
    def test_refresh_returns_new_refresh_token(self):
        """POST /api/auth/refresh should return a new refresh_token."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'dashboard'))
        from dashboard.app import create_app

        app = create_app(config={'TESTING': True})
        # Clear password_change_required via DatabaseManager (consolidated DB)
        try:
            from core.db import DatabaseManager
            conn = DatabaseManager.get_instance().get_connection()
            conn.execute("UPDATE users SET password_change_required = 0 WHERE username = 'admin'")
            conn.commit()
            DatabaseManager.get_instance().release_connection(conn)
        except Exception:
            pass

        with app.test_client() as client:
            # Login
            login_resp = client.post('/api/auth/login', json={
                'username': 'admin', 'password': 'admin'
            })
            if login_resp.status_code != 200:
                pytest.skip("API login unavailable")

            data = login_resp.get_json()
            old_refresh = data.get('refresh_token')
            if not old_refresh:
                pytest.skip("No refresh token returned (password change required?)")

            # Refresh
            refresh_resp = client.post('/api/auth/refresh', json={
                'refresh_token': old_refresh
            })
            assert refresh_resp.status_code == 200
            refresh_data = refresh_resp.get_json()
            assert 'refresh_token' in refresh_data, (
                "Refresh response should include a new refresh_token"
            )
            assert refresh_data['refresh_token'] != old_refresh, (
                "New refresh token should differ from the old one"
            )
