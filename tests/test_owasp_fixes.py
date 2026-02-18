"""
Tests for OWASP security fixes.

OWASP Top 10 2021 coverage:
- Fix 1 (A07:2021): Forced password change for default credentials
- Fix 2 (A07:2021): Redis-backed token blacklist for session invalidation
- Fix 3 (A02:2021, A09:2021): Log redaction for sensitive data

Run with: pytest tests/test_owasp_fixes.py -v
"""
import os
import pytest
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Fix 3: Log Redaction Tests (A02:2021 - Cryptographic Failures)
# =============================================================================

class TestLogRedaction:
    """Tests for sensitive data redaction in logs."""

    def test_password_redacted(self):
        """Password values should be redacted."""
        from core.event_logger import _redact_sensitive
        text = "password=MySecret123"
        result = _redact_sensitive(text)
        assert "MySecret123" not in result
        assert "REDACTED" in result

    def test_password_colon_syntax(self):
        """Password with colon syntax should be redacted."""
        from core.event_logger import _redact_sensitive
        text = "password: secret_value"
        result = _redact_sensitive(text)
        assert "secret_value" not in result
        assert "REDACTED" in result

    def test_bearer_token_redacted(self):
        """Bearer tokens should be redacted."""
        from core.event_logger import _redact_sensitive
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx"
        result = _redact_sensitive(text)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED" in result

    def test_cisco_enable_secret_redacted(self):
        """Cisco enable secrets should be redacted."""
        from core.event_logger import _redact_sensitive
        text = "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0"
        result = _redact_sensitive(text)
        assert "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0" not in result
        assert "REDACTED" in result

    def test_cisco_username_password_redacted(self):
        """Cisco username password config should be redacted."""
        from core.event_logger import _redact_sensitive
        text = "username admin secret 5 $1$abc$xyz123"
        result = _redact_sensitive(text)
        assert "$1$abc$xyz123" not in result
        assert "REDACTED" in result

    def test_json_secrets_redacted(self):
        """JSON-style secrets should be redacted."""
        from core.event_logger import _redact_sensitive
        text = '{"password": "secret123", "username": "admin"}'
        result = _redact_sensitive(text)
        assert "secret123" not in result
        assert "admin" in result  # Username preserved

    def test_api_key_redacted(self):
        """API keys should be redacted."""
        from core.event_logger import _redact_sensitive
        fake_key = "sk" + "_live_" + "1234567890abcdef"
        text = f"api_key={fake_key}"
        result = _redact_sensitive(text)
        assert fake_key not in result
        assert "REDACTED" in result

    def test_auth_token_redacted(self):
        """Auth tokens should be redacted."""
        from core.event_logger import _redact_sensitive
        fake_token = "tok" + "_abc123456789xyz"
        text = f"auth-token: {fake_token}"
        result = _redact_sensitive(text)
        assert fake_token not in result
        assert "REDACTED" in result

    def test_non_sensitive_preserved(self):
        """Non-sensitive data should not be redacted."""
        from core.event_logger import _redact_sensitive
        text = "tokenize the input string"
        result = _redact_sensitive(text)
        assert result == text  # No false positive

    def test_normal_text_preserved(self):
        """Normal text without sensitive data should be unchanged."""
        from core.event_logger import _redact_sensitive
        text = "show ip route ospf"
        result = _redact_sensitive(text)
        assert result == text

    def test_large_string_skipped(self):
        """Very large strings skip redaction for performance."""
        from core.event_logger import _redact_sensitive, MAX_REDACTION_LENGTH
        text = "password=secret " * 10000  # > 10KB
        assert len(text) > MAX_REDACTION_LENGTH
        result = _redact_sensitive(text)
        assert result == text  # Unchanged

    def test_empty_string_handled(self):
        """Empty string should not cause error."""
        from core.event_logger import _redact_sensitive
        assert _redact_sensitive("") == ""

    def test_none_handled(self):
        """None should be handled gracefully."""
        from core.event_logger import _redact_sensitive
        assert _redact_sensitive(None) is None


# =============================================================================
# Fix 2: Redis Token Blacklist Tests (A07:2021 - Authentication Failures)
# =============================================================================

class TestRedisTokenBlacklist:
    """Tests for Redis-backed token blacklist."""

    def test_blacklist_status_function_exists(self):
        """get_redis_blacklist_status should exist and return dict."""
        from dashboard.auth import get_redis_blacklist_status
        status = get_redis_blacklist_status()
        assert isinstance(status, dict)
        assert "available" in status
        assert "backend" in status

    def test_blacklist_status_reports_backend(self):
        """Status should report backend type."""
        from dashboard.auth import get_redis_blacklist_status
        status = get_redis_blacklist_status()
        assert status.get("backend") in ("redis", "in-memory")

    def test_blacklist_token_function_exists(self):
        """blacklist_token function should exist."""
        from dashboard.auth import blacklist_token
        assert callable(blacklist_token)

    def test_is_token_blacklisted_function_exists(self):
        """is_token_blacklisted function should exist."""
        from dashboard.auth import is_token_blacklisted
        assert callable(is_token_blacklisted)

    def test_in_memory_fallback_works(self, monkeypatch):
        """When Redis unavailable, falls back to in-memory."""
        monkeypatch.setenv("USE_REDIS_BLACKLIST", "false")

        # Re-import to pick up new env
        import importlib
        import dashboard.auth
        importlib.reload(dashboard.auth)

        from dashboard.auth import blacklist_token, is_token_blacklisted, _token_blacklist
        from datetime import datetime, timedelta

        test_jti = "test-jti-fallback-123"
        expires = datetime.now() + timedelta(hours=1)

        # Blacklist and check
        blacklist_token(test_jti, expires)
        # Note: in-memory fallback uses set, not Redis
        assert test_jti in _token_blacklist or is_token_blacklisted(test_jti)


# =============================================================================
# Fix 1: Password Change Required Tests (A07:2021 - Authentication Failures)
# =============================================================================

class TestPasswordChangeRequired:
    """Tests for forced password change on default credentials."""

    def test_helper_functions_exist(self):
        """Helper functions should exist."""
        from dashboard.auth import check_password_change_required, clear_password_change_required
        assert callable(check_password_change_required)
        assert callable(clear_password_change_required)

    def test_password_change_check_returns_bool(self):
        """check_password_change_required should return boolean."""
        from dashboard.auth import check_password_change_required
        result = check_password_change_required("nonexistent_user")
        assert isinstance(result, bool)

    def test_decorator_defined(self):
        """password_change_check decorator should be importable."""
        # The decorator is in api_server, not auth
        import dashboard.api_server
        assert hasattr(dashboard.api_server, 'password_change_check')

    def test_enforce_flag_configurable(self):
        """ENFORCE_PASSWORD_CHANGE flag should be configurable."""
        import dashboard.api_server
        assert hasattr(dashboard.api_server, 'ENFORCE_PASSWORD_CHANGE')


# =============================================================================
# Security Health Endpoint Tests
# =============================================================================

class TestSecurityHealthEndpoint:
    """Tests for /api/health/security endpoint."""

    @pytest.fixture
    def client(self):
        """Create Flask test client."""
        import dashboard.api_server
        dashboard.api_server.app.testing = True
        return dashboard.api_server.app.test_client()

    def test_security_health_returns_200(self, client):
        """Security health endpoint should return 200."""
        response = client.get('/api/health/security')
        assert response.status_code == 200

    def test_security_health_has_required_fields(self, client):
        """Security health should have required fields."""
        response = client.get('/api/health/security')
        data = response.get_json()

        assert "system_status" in data
        assert "token_blacklist" in data
        assert "features" in data
        assert "timestamp" in data

    def test_security_health_reports_features(self, client):
        """Security health should report feature flags."""
        response = client.get('/api/health/security')
        data = response.get_json()

        features = data.get("features", {})
        assert "password_change_enforcement" in features
        assert "log_redaction" in features
        assert "redis_blacklist" in features

    def test_security_health_reports_blacklist_status(self, client):
        """Security health should report blacklist status."""
        response = client.get('/api/health/security')
        data = response.get_json()

        blacklist = data.get("token_blacklist", {})
        assert "available" in blacklist
        assert "backend" in blacklist


# =============================================================================
# Integration Tests (require running API)
# =============================================================================

@pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to run integration tests"
)
class TestOWASPIntegration:
    """Integration tests for OWASP fixes (require running API)."""

    @pytest.fixture
    def api_base(self):
        """API base URL."""
        return os.getenv("API_BASE", "http://localhost:5001")

    def test_login_returns_password_change_flag(self, api_base):
        """Login should return password_change_required field."""
        import requests
        response = requests.post(
            f"{api_base}/api/auth/login",
            json={"username": "admin", "password": "admin"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            assert "password_change_required" in data

    def test_security_health_accessible(self, api_base):
        """Security health endpoint should be accessible."""
        import requests
        response = requests.get(f"{api_base}/api/health/security", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert "system_status" in data
