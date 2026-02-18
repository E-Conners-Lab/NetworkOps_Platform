#!/usr/bin/env python3
"""
Authentication Baseline Tests

Captures current authentication behavior before implementing:
- HashiCorp Vault integration
- TOTP MFA
- Single Session Management

Run before and after changes to ensure backward compatibility.

Usage:
    pytest tests/test_auth_baseline.py -v
    pytest tests/test_auth_baseline.py -v --tb=short  # shorter traceback
"""

import os
import sys
import pytest
import requests
import time
from dataclasses import dataclass
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# API base URL - can be overridden with environment variable
API_BASE = os.getenv("API_BASE", "http://localhost:5001")

# Delay between tests to avoid rate limiting (10 requests per minute limit)
TEST_DELAY = 2.0  # Increased to handle rate limiting better

# Module-level token cache to reduce login calls
_token_cache = {}


@dataclass
class AuthTokens:
    """Holds authentication tokens"""
    access_token: str
    refresh_token: Optional[str] = None
    username: str = ""


def get_cached_token(base_url: str, username: str, password: str, session: requests.Session) -> tuple[int, dict]:
    """Get cached token or login"""
    cache_key = f"{base_url}:{username}"
    if cache_key not in _token_cache:
        resp = session.post(
            f"{base_url}/api/auth/login",
            json={"username": username, "password": password}
        )
        if resp.status_code == 200:
            _token_cache[cache_key] = resp.json()
            return 200, _token_cache[cache_key]
        return resp.status_code, {}
    return 200, _token_cache[cache_key]


class TestAuthBaseline:
    """Baseline tests for current authentication system"""

    @pytest.fixture(scope="class", autouse=True)
    def class_setup(self):
        """One-time setup for test class - wait for rate limits to reset"""
        # Wait for any previous rate limits to expire
        time.sleep(5)
        yield
        # Cleanup after all tests
        _token_cache.clear()

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup for each test"""
        self.base_url = API_BASE
        self.session = requests.Session()
        # Suppress SSL warnings for local testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session.verify = False
        # Add delay between tests to avoid rate limiting
        time.sleep(TEST_DELAY)

    def _login(self, username: str, password: str, use_cache: bool = False, retry_on_rate_limit: bool = True) -> tuple[int, dict]:
        """Helper to perform login. use_cache=True for tests that just need a token."""
        if use_cache:
            return get_cached_token(self.base_url, username, password, self.session)

        max_retries = 3 if retry_on_rate_limit else 1
        for attempt in range(max_retries):
            resp = self.session.post(
                f"{self.base_url}/api/auth/login",
                json={"username": username, "password": password}
            )
            if resp.status_code == 429 and retry_on_rate_limit and attempt < max_retries - 1:
                # Rate limited - wait and retry
                retry_after = int(resp.headers.get('Retry-After', 10))
                time.sleep(min(retry_after, 15))  # Wait up to 15 seconds
                continue
            break
        return resp.status_code, resp.json() if resp.status_code == 200 else resp.json() if resp.text else {}

    def _get_with_token(self, endpoint: str, token: str) -> requests.Response:
        """Helper to make authenticated GET request"""
        return self.session.get(
            f"{self.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {token}"}
        )

    def _post_with_token(self, endpoint: str, token: str, data: dict) -> requests.Response:
        """Helper to make authenticated POST request"""
        return self.session.post(
            f"{self.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {token}"},
            json=data
        )

    # =========================================================================
    # 1. Login Flow Tests
    # =========================================================================

    def test_login_returns_access_token(self):
        """Login should return an access token"""
        status, data = self._login("admin", "admin")

        assert status == 200, f"Login failed with status {status}"
        assert "token" in data, "Response missing 'token' field"
        assert len(data["token"]) > 50, "Token appears too short"

    def test_login_returns_refresh_token(self):
        """Login should return a refresh token"""
        status, data = self._login("admin", "admin")

        assert status == 200
        assert "refresh_token" in data, "Response missing 'refresh_token' field"
        assert len(data["refresh_token"]) > 50, "Refresh token appears too short"

    def test_login_returns_user_info(self):
        """Login should return username, groups, and permissions"""
        status, data = self._login("admin", "admin")

        assert status == 200
        assert "username" in data, "Response missing 'username' field"
        assert "groups" in data, "Response missing 'groups' field"
        assert "permissions" in data, "Response missing 'permissions' field"
        assert data["username"] == "admin"

    def test_login_invalid_password(self):
        """Invalid password should return 401"""
        resp = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )

        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    def test_login_invalid_username(self):
        """Invalid username should return 401"""
        resp = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": "nonexistent", "password": "password"}
        )

        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"

    def test_login_missing_fields(self):
        """Missing fields should return 400"""
        # Missing password
        resp = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": "admin"}
        )
        assert resp.status_code == 400, f"Expected 400 for missing password, got {resp.status_code}"

        # Missing username
        resp = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"password": "admin"}
        )
        assert resp.status_code == 400, f"Expected 400 for missing username, got {resp.status_code}"

    # =========================================================================
    # 2. Token Validation Tests
    # =========================================================================

    def test_token_grants_access_to_protected_endpoint(self):
        """Valid token should grant access to /api/auth/me"""
        status, data = self._login("admin", "admin", use_cache=True)
        assert status == 200

        token = data["token"]
        resp = self._get_with_token("/api/auth/me", token)

        assert resp.status_code == 200, f"Protected endpoint returned {resp.status_code}"
        me_data = resp.json()
        assert "username" in me_data
        assert me_data["username"] == "admin"

    def test_invalid_token_rejected(self):
        """Invalid token should be rejected with 401"""
        resp = self._get_with_token("/api/auth/me", "invalid.token.here")

        assert resp.status_code == 401, f"Expected 401 for invalid token, got {resp.status_code}"

    def test_missing_token_rejected(self):
        """Missing token should be rejected with 401"""
        resp = self.session.get(f"{self.base_url}/api/auth/me")

        assert resp.status_code == 401, f"Expected 401 for missing token, got {resp.status_code}"

    def test_me_endpoint_returns_user_info(self):
        """GET /api/auth/me should return username and role"""
        status, data = self._login("admin", "admin", use_cache=True)
        assert status == 200

        token = data["token"]
        resp = self._get_with_token("/api/auth/me", token)

        assert resp.status_code == 200
        me_data = resp.json()
        assert "username" in me_data, "Response missing 'username' field"
        assert "role" in me_data, "Response missing 'role' field"
        assert me_data["username"] == "admin"

    # =========================================================================
    # 3. Refresh Token Flow Tests
    # =========================================================================

    def test_refresh_token_returns_new_access_token(self):
        """Refresh endpoint should return a new access token"""
        status, data = self._login("admin", "admin")
        assert status == 200

        refresh_token = data["refresh_token"]

        resp = self.session.post(
            f"{self.base_url}/api/auth/refresh",
            json={"refresh_token": refresh_token}
        )

        assert resp.status_code == 200, f"Refresh failed with {resp.status_code}"
        new_data = resp.json()
        assert "token" in new_data, "Refresh response missing 'token'"
        assert new_data["token"] != data["token"], "New token should be different"

    def test_invalid_refresh_token_rejected(self):
        """Invalid refresh token should be rejected"""
        resp = self.session.post(
            f"{self.base_url}/api/auth/refresh",
            json={"refresh_token": "invalid.refresh.token"}
        )

        assert resp.status_code == 401, f"Expected 401 for invalid refresh token, got {resp.status_code}"

    def test_access_token_not_accepted_as_refresh_token(self):
        """Access token should not work as refresh token"""
        status, data = self._login("admin", "admin")
        assert status == 200

        # Try to use access token as refresh token
        resp = self.session.post(
            f"{self.base_url}/api/auth/refresh",
            json={"refresh_token": data["token"]}  # Using access token
        )

        assert resp.status_code == 401, f"Access token should not work as refresh, got {resp.status_code}"

    # =========================================================================
    # 4. Logout Tests
    # =========================================================================

    def test_logout_invalidates_access_token(self):
        """Logout should invalidate the access token"""
        # Clear cache and wait for rate limits to reset
        _token_cache.clear()
        time.sleep(15)

        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200, f"Login failed with {status} - may be rate limited"

        token = data["token"]
        refresh_token = data.get("refresh_token")

        # Verify token works before logout
        resp = self._get_with_token("/api/auth/me", token)
        assert resp.status_code == 200, "Token should work before logout"

        # Logout
        logout_resp = self._post_with_token("/api/auth/logout", token, {
            "refresh_token": refresh_token
        })
        assert logout_resp.status_code == 200, f"Logout failed with {logout_resp.status_code}"

        # Verify token no longer works
        resp = self._get_with_token("/api/auth/me", token)
        assert resp.status_code == 401, f"Token should be invalid after logout, got {resp.status_code}"

        # Clear cache since we logged out
        _token_cache.clear()

    def test_logout_invalidates_refresh_token(self):
        """Logout should invalidate the refresh token"""
        # Clear cache and wait for rate limits to reset
        _token_cache.clear()
        time.sleep(15)

        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200, f"Login failed with {status} - may be rate limited"

        token = data["token"]
        refresh_token = data["refresh_token"]

        # Logout
        self._post_with_token("/api/auth/logout", token, {
            "refresh_token": refresh_token
        })

        # Try to refresh with old refresh token
        resp = self.session.post(
            f"{self.base_url}/api/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert resp.status_code == 401, f"Refresh token should be invalid after logout, got {resp.status_code}"

        # Clear cache since we logged out
        _token_cache.clear()

    # =========================================================================
    # 5. Rate Limiting Tests
    # =========================================================================

    def test_auth_rate_limiting_exists(self):
        """Auth endpoint should have rate limiting"""
        # Make many rapid requests using non-existent usernames
        # to avoid triggering account lockout on admin
        rate_limited = False
        for i in range(15):
            resp = self.session.post(
                f"{self.base_url}/api/auth/login",
                json={"username": f"rate_limit_test_user_{i}", "password": "wrongpassword"}
            )
            if resp.status_code == 429:
                rate_limited = True
                break

        assert rate_limited, "Auth endpoint should have rate limiting (expected 429 after many requests)"

        # Clear cache and wait since we just triggered rate limiting
        _token_cache.clear()
        time.sleep(20)

    # =========================================================================
    # 6. Password Validation Tests
    # =========================================================================

    def test_password_complexity_enforced(self):
        """Weak passwords should be rejected"""
        # First login as admin to create test user
        status, data = self._login("admin", "admin", use_cache=True)
        assert status == 200
        token = data["token"]

        weak_passwords = [
            "short",          # Too short
            "alllowercase1!", # Missing uppercase
            "ALLUPPERCASE1!", # Missing lowercase
            "NoDigitsHere!",  # Missing digit
            "NoSpecial123",   # Missing special char
        ]

        for weak_pass in weak_passwords:
            resp = self._post_with_token("/api/auth/users", token, {
                "username": f"test_{weak_pass[:5]}",
                "password": weak_pass,
                "role": "operator"
            })
            assert resp.status_code != 201, f"Weak password '{weak_pass}' should be rejected"

            # Cleanup if accidentally created
            if resp.status_code == 201:
                self.session.delete(
                    f"{self.base_url}/api/auth/users/test_{weak_pass[:5]}?hard=true",
                    headers={"Authorization": f"Bearer {token}"}
                )

    def test_strong_password_accepted(self):
        """Strong password should be accepted"""
        # Fresh login since previous tests may have triggered rate limiting
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200
        token = data["token"]

        strong_password = "StrongPass123!"

        resp = self._post_with_token("/api/auth/users", token, {
            "username": "test_strong_pass",
            "password": strong_password,
            "role": "operator"
        })

        try:
            assert resp.status_code == 201, f"Strong password should be accepted, got {resp.status_code}"
        finally:
            # Cleanup
            self.session.delete(
                f"{self.base_url}/api/auth/users/test_strong_pass?hard=true",
                headers={"Authorization": f"Bearer {token}"}
            )

    # =========================================================================
    # 7. Account Lockout Tests
    # =========================================================================

    def test_account_lockout_after_failed_attempts(self):
        """Account should lock after multiple failed attempts"""
        # Clear cache and wait for rate limits to fully reset
        _token_cache.clear()
        time.sleep(20)

        # Get fresh admin token
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200, f"Admin login failed with {status}"
        token = data["token"]

        test_user = f"lockout_test_{int(time.time())}"
        create_resp = self._post_with_token("/api/auth/users", token, {
            "username": test_user,
            "password": "TestPass123!",
            "role": "operator"
        })
        assert create_resp.status_code == 201, f"Failed to create test user: {create_resp.text}"

        try:
            # Make multiple failed login attempts with delays to avoid rate limiting
            locked = False
            # Lockout threshold is typically 5 attempts, try up to 8
            for i in range(8):
                time.sleep(3)  # Delay between attempts
                resp = self.session.post(
                    f"{self.base_url}/api/auth/login",
                    json={"username": test_user, "password": "wrongpassword"}
                )
                # Handle rate limiting - wait and retry
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get('Retry-After', 30))
                    time.sleep(min(retry_after, 30))
                    # Don't count rate-limited requests
                    continue
                if "locked" in resp.text.lower():
                    locked = True
                    break

            assert locked, f"Account should lock after multiple failed attempts. Last response: {resp.text[:200]}"
        finally:
            # Cleanup - get fresh token if needed
            _token_cache.clear()
            time.sleep(10)
            status, data = self._login("admin", "admin", retry_on_rate_limit=True)
            if status == 200:
                self.session.delete(
                    f"{self.base_url}/api/auth/users/{test_user}?hard=true",
                    headers={"Authorization": f"Bearer {data['token']}"}
                )
            _token_cache.clear()

    # =========================================================================
    # 8. Response Schema Tests
    # =========================================================================

    def test_login_response_schema(self):
        """Login response should have expected schema"""
        # Fresh login since previous tests may have logged out
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200

        # Required fields (note: groups and permissions, not role)
        required_fields = ["token", "refresh_token", "username", "groups", "permissions"]
        for field in required_fields:
            assert field in data, f"Login response missing required field: {field}"

        # Types
        assert isinstance(data["token"], str)
        assert isinstance(data["refresh_token"], str)
        assert isinstance(data["username"], str)
        assert isinstance(data["groups"], list)
        assert isinstance(data["permissions"], list)

    def test_me_response_schema(self):
        """GET /api/auth/me response should have expected schema"""
        # Fresh login since previous tests may have logged out
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200

        resp = self._get_with_token("/api/auth/me", data["token"])
        me_data = resp.json()

        # Required fields (note: only username and role)
        required_fields = ["username", "role"]
        for field in required_fields:
            assert field in me_data, f"/api/auth/me response missing required field: {field}"

        # Types
        assert isinstance(me_data["username"], str)
        assert isinstance(me_data["role"], str)

    def test_refresh_response_schema(self):
        """Refresh response should have expected schema"""
        # Fresh login since previous tests may have logged out
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200

        resp = self.session.post(
            f"{self.base_url}/api/auth/refresh",
            json={"refresh_token": data["refresh_token"]}
        )
        refresh_data = resp.json()

        assert "token" in refresh_data, "Refresh response missing 'token'"
        assert isinstance(refresh_data["token"], str)

    # =========================================================================
    # 9. Permission Tests
    # =========================================================================

    def test_admin_has_manage_users_permission(self):
        """Admin user should have manage_users permission (from login response)"""
        # Fresh login since previous tests may have logged out
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200

        # Permissions are returned in login response, not /api/auth/me
        assert "manage_users" in data.get("permissions", []), \
            "Admin should have manage_users permission"

    def test_admin_can_list_users(self):
        """Admin should be able to list users"""
        # Fresh login since previous tests may have logged out
        status, data = self._login("admin", "admin", retry_on_rate_limit=True)
        assert status == 200

        resp = self._get_with_token("/api/auth/users", data["token"])

        assert resp.status_code == 200, f"Admin should access /api/auth/users, got {resp.status_code}"
        users = resp.json()
        assert isinstance(users, list), "Users response should be a list"


class TestAuthBaselineHealthEndpoints:
    """Test health endpoints don't require auth"""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.base_url = API_BASE
        self.session = requests.Session()
        self.session.verify = False

    def test_healthz_no_auth_required(self):
        """/healthz should not require authentication"""
        resp = self.session.get(f"{self.base_url}/healthz")
        assert resp.status_code == 200

    def test_readyz_no_auth_required(self):
        """/readyz should not require authentication"""
        resp = self.session.get(f"{self.base_url}/readyz")
        # Readiness probe returns 200 (ok/degraded) or 503 (unavailable) - both are valid
        # The key test is that we don't get 401/403 (auth required)
        assert resp.status_code in (200, 503), f"Expected 200 or 503, got {resp.status_code}"
        assert resp.status_code != 401, "/readyz should not require authentication"
        assert resp.status_code != 403, "/readyz should not require authorization"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
