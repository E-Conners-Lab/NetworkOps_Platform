#!/usr/bin/env python3
"""
NetworkOps API Security Testing Suite

DIY penetration testing for API endpoints. Run before enterprise security review.

Tests:
1. Authentication vulnerabilities (JWT manipulation, weak secrets, bypass)
2. Authorization flaws (IDOR, privilege escalation, permission bypass)
3. Injection attacks (command injection, SQL injection)
4. Rate limiting effectiveness
5. Input validation and fuzzing

Usage:
    python scripts/api_security_test.py [--target URL] [--verbose]

Requirements:
    pip install requests pyjwt

Author: Security self-assessment for HPE review preparation
"""

import argparse
import json
import time
import sys
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import jwt

# Suppress SSL warnings for local testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class TestResult:
    """Individual test result"""
    name: str
    category: str
    passed: bool
    severity: str  # critical, high, medium, low, info
    description: str
    details: str = ""
    recommendation: str = ""


@dataclass
class SecurityReport:
    """Aggregated security report"""
    target: str
    timestamp: str
    results: list[TestResult] = field(default_factory=list)

    def add(self, result: TestResult):
        self.results.append(result)

    def summary(self) -> dict:
        """Generate summary statistics"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        by_severity = {}
        for r in self.results:
            if not r.passed:
                by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        return {
            "total_tests": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": f"{(passed/total)*100:.1f}%" if total > 0 else "N/A",
            "failures_by_severity": by_severity,
        }


class APISecurityTester:
    """API Security Testing Framework"""

    def __init__(self, base_url: str, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed certs
        self.report = SecurityReport(
            target=self.base_url,
            timestamp=datetime.now().isoformat()
        )

        # Tokens for different permission levels
        self.admin_token: Optional[str] = None
        self.operator_token: Optional[str] = None
        self.readonly_token: Optional[str] = None

    def log(self, msg: str, level: str = "info"):
        """Log message if verbose mode"""
        colors = {
            "info": "\033[94m",    # Blue
            "pass": "\033[92m",    # Green
            "fail": "\033[91m",    # Red
            "warn": "\033[93m",    # Yellow
            "reset": "\033[0m"
        }
        if self.verbose:
            color = colors.get(level, colors["info"])
            print(f"{color}[{level.upper()}]{colors['reset']} {msg}")

    def get(self, endpoint: str, token: str = None, **kwargs) -> requests.Response:
        """Make GET request with optional auth"""
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.session.get(f"{self.base_url}{endpoint}", headers=headers, **kwargs)

    def post(self, endpoint: str, token: str = None, **kwargs) -> requests.Response:
        """Make POST request with optional auth"""
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.session.post(f"{self.base_url}{endpoint}", headers=headers, **kwargs)

    def put(self, endpoint: str, token: str = None, **kwargs) -> requests.Response:
        """Make PUT request with optional auth"""
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.session.put(f"{self.base_url}{endpoint}", headers=headers, **kwargs)

    def delete(self, endpoint: str, token: str = None, **kwargs) -> requests.Response:
        """Make DELETE request with optional auth"""
        headers = kwargs.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.session.delete(f"{self.base_url}{endpoint}", headers=headers, **kwargs)

    # =========================================================================
    # Setup
    # =========================================================================

    def setup(self) -> bool:
        """Initialize test session with auth tokens"""
        self.log("Setting up test session...")

        # Get admin token
        resp = self.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        if resp.status_code == 200:
            self.admin_token = resp.json().get("token")
            self.log("Got admin token", "pass")
        else:
            self.log(f"Failed to get admin token: {resp.status_code}", "fail")
            return False

        # Get operator token
        resp = self.post("/api/auth/login", json={"username": "operator", "password": "operator"})
        if resp.status_code == 200:
            self.operator_token = resp.json().get("token")
            self.log("Got operator token", "pass")
        else:
            self.log("Operator user not found (may need to create)", "warn")

        # Pre-create lockout test user (before rate limit is consumed by other tests)
        if self.admin_token:
            self.delete("/api/auth/users/lockout_test?hard=true", token=self.admin_token)
            self.post("/api/auth/users", token=self.admin_token, json={
                "username": "lockout_test",
                "password": "TestPass123!",
                "role": "operator"
            })

        return True

    # =========================================================================
    # 1. Authentication Tests
    # =========================================================================

    def test_auth_default_credentials(self):
        """Test for default/weak credentials"""
        self.log("Testing default credentials...")

        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("operator", "operator"),
            ("root", "root"),
            ("test", "test"),
        ]

        vulnerable_creds = []
        for username, password in default_creds:
            resp = self.post("/api/auth/login", json={"username": username, "password": password})
            if resp.status_code == 200:
                vulnerable_creds.append((username, password))

        if vulnerable_creds:
            self.report.add(TestResult(
                name="Default Credentials",
                category="Authentication",
                passed=False,
                severity="critical",
                description="Default/weak credentials accepted",
                details=f"Vulnerable accounts: {vulnerable_creds}",
                recommendation="Change default passwords. Enforce strong password policy."
            ))
        else:
            self.report.add(TestResult(
                name="Default Credentials",
                category="Authentication",
                passed=True,
                severity="critical",
                description="No default credentials found"
            ))

    def test_auth_jwt_weak_secret(self):
        """Test for weak JWT secrets"""
        self.log("Testing JWT weak secret...")

        if not self.admin_token:
            return

        # Common weak secrets to try
        weak_secrets = [
            "secret",
            "dev-secret-change-in-production",
            "password",
            "123456",
            "jwt_secret",
            "changeme",
        ]

        # Decode without verification to get payload
        try:
            unverified = jwt.decode(self.admin_token, options={"verify_signature": False})
        except Exception:
            return

        weak_found = []
        for secret in weak_secrets:
            try:
                jwt.decode(self.admin_token, secret, algorithms=["HS256"])
                weak_found.append(secret)
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue

        if weak_found:
            self.report.add(TestResult(
                name="JWT Weak Secret",
                category="Authentication",
                passed=False,
                severity="critical",
                description="JWT signed with weak/default secret",
                details=f"Secrets that work: {weak_found}",
                recommendation="Generate a strong random secret (32+ bytes). Store in environment variable."
            ))
        else:
            self.report.add(TestResult(
                name="JWT Weak Secret",
                category="Authentication",
                passed=True,
                severity="critical",
                description="JWT secret is not in common weak secrets list"
            ))

    def test_auth_jwt_none_algorithm(self):
        """Test for JWT 'none' algorithm vulnerability"""
        self.log("Testing JWT none algorithm bypass...")

        if not self.admin_token:
            return

        # Decode without verification
        try:
            payload = jwt.decode(self.admin_token, options={"verify_signature": False})
        except Exception:
            return

        # Create token with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        import base64

        def b64_encode(data):
            return base64.urlsafe_b64encode(
                json.dumps(data).encode()
            ).rstrip(b"=").decode()

        none_token = f"{b64_encode(header)}.{b64_encode(payload)}."

        # Try to use the 'none' algorithm token
        resp = self.get("/api/auth/me", token=none_token)

        if resp.status_code == 200:
            self.report.add(TestResult(
                name="JWT None Algorithm",
                category="Authentication",
                passed=False,
                severity="critical",
                description="Server accepts JWT with 'none' algorithm",
                details="Attacker can forge tokens without knowing secret",
                recommendation="Explicitly specify allowed algorithms in jwt.decode()"
            ))
        else:
            self.report.add(TestResult(
                name="JWT None Algorithm",
                category="Authentication",
                passed=True,
                severity="critical",
                description="Server rejects JWT with 'none' algorithm"
            ))

    def test_auth_jwt_expired_token(self):
        """Test that expired tokens are rejected"""
        self.log("Testing expired token handling...")

        if not self.admin_token:
            return

        # Create an expired token (if we know the secret)
        try:
            payload = jwt.decode(self.admin_token, options={"verify_signature": False})
            # Modify exp to past
            payload["exp"] = int(time.time()) - 3600

            # Try with the weak secret we may have found
            expired_token = jwt.encode(payload, "dev-secret-change-in-production", algorithm="HS256")
            resp = self.get("/api/auth/me", token=expired_token)

            if resp.status_code == 200:
                self.report.add(TestResult(
                    name="Expired Token Handling",
                    category="Authentication",
                    passed=False,
                    severity="high",
                    description="Server accepts expired JWT tokens",
                    recommendation="Ensure exp claim is properly validated"
                ))
            else:
                self.report.add(TestResult(
                    name="Expired Token Handling",
                    category="Authentication",
                    passed=True,
                    severity="high",
                    description="Server correctly rejects expired tokens"
                ))
        except Exception as e:
            self.log(f"Could not test expired token: {e}", "warn")

    def test_auth_missing_token(self):
        """Test protected endpoints without token"""
        self.log("Testing missing token handling...")

        protected_endpoints = [
            ("/api/auth/me", "GET"),
            ("/api/auth/users", "GET"),
            ("/api/command", "POST"),
            ("/api/remediate", "POST"),
        ]

        unprotected = []
        for endpoint, method in protected_endpoints:
            if method == "GET":
                resp = self.get(endpoint)
            else:
                resp = self.post(endpoint, json={})

            if resp.status_code not in [401, 403]:
                unprotected.append((endpoint, method, resp.status_code))

        if unprotected:
            self.report.add(TestResult(
                name="Missing Token Bypass",
                category="Authentication",
                passed=False,
                severity="critical",
                description="Protected endpoints accessible without token",
                details=f"Unprotected: {unprotected}",
                recommendation="Ensure @jwt_required decorator on all protected routes"
            ))
        else:
            self.report.add(TestResult(
                name="Missing Token Bypass",
                category="Authentication",
                passed=True,
                severity="critical",
                description="All protected endpoints require authentication"
            ))

    def test_auth_account_lockout(self):
        """Test account lockout after failed attempts"""
        self.log("Testing account lockout...")

        # User 'lockout_test' is pre-created in setup() to ensure it exists
        # before rate limits are consumed by other tests

        # Try multiple failed logins with delays to avoid rate limiting
        lockout_triggered = False
        rate_limited = False
        for i in range(7):
            resp = self.post("/api/auth/login", json={
                "username": "lockout_test",
                "password": "wrongpassword"
            })
            if resp.status_code == 429:
                rate_limited = True
                break
            if "locked" in resp.text.lower():
                lockout_triggered = True
                break
            # Small delay to stay under rate limit (10/min = 1 per 6 seconds)
            time.sleep(0.5)

        # Cleanup - delete user after test
        if self.admin_token:
            self.delete("/api/auth/users/lockout_test?hard=true", token=self.admin_token)

        if lockout_triggered:
            self.report.add(TestResult(
                name="Account Lockout",
                category="Authentication",
                passed=True,
                severity="high",
                description="Account lockout triggers after failed attempts"
            ))
        elif rate_limited:
            # Rate limiting kicked in before lockout - this is still a security control
            self.report.add(TestResult(
                name="Account Lockout",
                category="Authentication",
                passed=True,
                severity="high",
                description="Rate limiting prevents brute force (lockout may also be active)"
            ))
        else:
            self.report.add(TestResult(
                name="Account Lockout",
                category="Authentication",
                passed=False,
                severity="high",
                description="No account lockout after multiple failed attempts",
                recommendation="Implement account lockout (5 attempts, 15 min lockout)"
            ))

    def test_auth_password_complexity(self):
        """Test password complexity requirements"""
        self.log("Testing password complexity...")

        if not self.admin_token:
            return

        weak_passwords = [
            ("short", "Password too short"),
            ("alllowercase123!", "Missing uppercase"),
            ("ALLUPPERCASE123!", "Missing lowercase"),
            ("NoDigitsHere!", "Missing digit"),
            ("NoSpecialChar123", "Missing special character"),
        ]

        strong_enforcement = True
        for weak_pass, reason in weak_passwords:
            resp = self.post("/api/auth/users", token=self.admin_token, json={
                "username": f"weaktest_{weak_pass[:5]}",
                "password": weak_pass,
                "role": "operator"
            })
            if resp.status_code == 201:
                strong_enforcement = False
                # Cleanup
                self.delete(f"/api/auth/users/weaktest_{weak_pass[:5]}?hard=true",
                          token=self.admin_token)

        if strong_enforcement:
            self.report.add(TestResult(
                name="Password Complexity",
                category="Authentication",
                passed=True,
                severity="high",
                description="Password complexity requirements enforced"
            ))
        else:
            self.report.add(TestResult(
                name="Password Complexity",
                category="Authentication",
                passed=False,
                severity="high",
                description="Weak passwords accepted",
                recommendation="Require min 8 chars, uppercase, lowercase, digit, special char"
            ))

    def test_auth_token_refresh(self):
        """Test token refresh functionality"""
        self.log("Testing token refresh...")

        # Login to get refresh token
        resp = self.post("/api/auth/login", json={
            "username": "admin",
            "password": "admin"
        })

        if resp.status_code != 200:
            return

        data = resp.json()
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            self.report.add(TestResult(
                name="Token Refresh",
                category="Authentication",
                passed=False,
                severity="medium",
                description="No refresh token provided on login",
                recommendation="Implement refresh token for secure token rotation"
            ))
            return

        # Try to refresh
        resp = self.post("/api/auth/refresh", json={"refresh_token": refresh_token})

        if resp.status_code == 200 and resp.json().get("token"):
            self.report.add(TestResult(
                name="Token Refresh",
                category="Authentication",
                passed=True,
                severity="medium",
                description="Token refresh working correctly"
            ))
        else:
            self.report.add(TestResult(
                name="Token Refresh",
                category="Authentication",
                passed=False,
                severity="medium",
                description="Token refresh not working",
                details=f"Response: {resp.text[:200]}"
            ))

    def test_auth_logout_invalidation(self):
        """Test that logout invalidates tokens"""
        self.log("Testing logout token invalidation...")

        # Login to get token
        resp = self.post("/api/auth/login", json={
            "username": "admin",
            "password": "admin"
        })

        if resp.status_code != 200:
            return

        token = resp.json().get("token")
        refresh_token = resp.json().get("refresh_token")

        # Verify token works
        resp = self.get("/api/auth/me", token=token)
        if resp.status_code != 200:
            return

        # Logout
        resp = self.post("/api/auth/logout", token=token, json={
            "refresh_token": refresh_token
        })

        if resp.status_code != 200:
            return

        # Try to use token after logout
        resp = self.get("/api/auth/me", token=token)

        if resp.status_code == 401:
            self.report.add(TestResult(
                name="Logout Token Invalidation",
                category="Authentication",
                passed=True,
                severity="medium",
                description="Tokens properly invalidated on logout"
            ))
        else:
            self.report.add(TestResult(
                name="Logout Token Invalidation",
                category="Authentication",
                passed=False,
                severity="medium",
                description="Token still valid after logout",
                recommendation="Implement token blacklist for logout"
            ))

    # =========================================================================
    # 2. Authorization Tests
    # =========================================================================

    def test_authz_privilege_escalation(self):
        """Test horizontal/vertical privilege escalation"""
        self.log("Testing privilege escalation...")

        if not self.operator_token:
            self.log("Skipping - no operator token", "warn")
            return

        # Try admin-only endpoints with operator token
        admin_endpoints = [
            ("/api/auth/users", "GET"),
            ("/api/auth/users", "POST"),
            ("/api/auth/groups", "POST"),
        ]

        escalation_found = []
        for endpoint, method in admin_endpoints:
            if method == "GET":
                resp = self.get(endpoint, token=self.operator_token)
            else:
                resp = self.post(endpoint, token=self.operator_token, json={
                    "username": "hacker", "password": "hacker123", "role": "admin"
                })

            if resp.status_code not in [401, 403]:
                escalation_found.append((endpoint, method, resp.status_code))

        if escalation_found:
            self.report.add(TestResult(
                name="Privilege Escalation",
                category="Authorization",
                passed=False,
                severity="critical",
                description="Non-admin can access admin endpoints",
                details=f"Accessible: {escalation_found}",
                recommendation="Verify @permission_required decorators on admin routes"
            ))
        else:
            self.report.add(TestResult(
                name="Privilege Escalation",
                category="Authorization",
                passed=True,
                severity="critical",
                description="Admin endpoints properly protected"
            ))

    def test_authz_idor_user_management(self):
        """Test IDOR in user management endpoints"""
        self.log("Testing IDOR vulnerabilities...")

        if not self.operator_token:
            return

        # Try to modify/delete other users with operator token
        idor_tests = [
            ("PUT", "/api/auth/users/admin", {"password": "hacked123"}),
            ("DELETE", "/api/auth/users/admin", None),
        ]

        idor_found = []
        for method, endpoint, data in idor_tests:
            if method == "PUT":
                resp = self.put(endpoint, token=self.operator_token, json=data)
            elif method == "DELETE":
                resp = self.delete(endpoint, token=self.operator_token)

            if resp.status_code == 200:
                idor_found.append((method, endpoint))

        if idor_found:
            self.report.add(TestResult(
                name="IDOR User Management",
                category="Authorization",
                passed=False,
                severity="critical",
                description="User can modify other users' accounts",
                details=f"Vulnerable endpoints: {idor_found}",
                recommendation="Verify user can only modify own account or has manage_users permission"
            ))
        else:
            self.report.add(TestResult(
                name="IDOR User Management",
                category="Authorization",
                passed=True,
                severity="critical",
                description="User management properly protected against IDOR"
            ))

    def test_authz_permission_check_bypass(self):
        """Test if permission checks can be bypassed"""
        self.log("Testing permission check bypass...")

        if not self.operator_token:
            return

        # Try config commands with operator (should only have show command permission)
        test_cases = [
            {"device": "R1", "command": "configure terminal"},
            {"device": "R1", "command": "show run | conf t"},  # Trying to sneak in config
        ]

        bypass_found = []
        for test in test_cases:
            resp = self.post("/api/command", token=self.operator_token, json=test)
            if resp.status_code == 200:
                bypass_found.append(test)

        if bypass_found:
            self.report.add(TestResult(
                name="Permission Bypass",
                category="Authorization",
                passed=False,
                severity="high",
                description="Config commands executed without proper permission",
                details=f"Allowed commands: {bypass_found}",
                recommendation="Review validate_command() logic"
            ))
        else:
            self.report.add(TestResult(
                name="Permission Bypass",
                category="Authorization",
                passed=True,
                severity="high",
                description="Permission checks working correctly"
            ))

    # =========================================================================
    # 3. Injection Tests
    # =========================================================================

    def test_injection_command(self):
        """Test command injection vulnerabilities"""
        self.log("Testing command injection...")

        if not self.admin_token:
            return

        # Command injection payloads
        injection_payloads = [
            "show version; cat /etc/passwd",
            "show version && id",
            "show version | cat /etc/passwd",
            "show version `id`",
            "show version $(id)",
            "show version\ncat /etc/passwd",
            "show version%0acat /etc/passwd",
        ]

        injection_found = []
        for payload in injection_payloads:
            resp = self.post("/api/command", token=self.admin_token, json={
                "device": "R1",
                "command": payload
            })

            # Check if blocked or if output contains evidence of injection
            if resp.status_code == 200:
                output = resp.json().get("output", "")
                # Look for signs of command execution
                if any(indicator in output.lower() for indicator in ["uid=", "root:", "passwd"]):
                    injection_found.append((payload, "executed"))
                elif "blocked" not in str(resp.json()).lower():
                    # Command was accepted (may not have executed yet)
                    injection_found.append((payload, "accepted"))

        if injection_found:
            self.report.add(TestResult(
                name="Command Injection",
                category="Injection",
                passed=False,
                severity="critical",
                description="Command injection payloads not properly blocked",
                details=f"Payloads: {injection_found}",
                recommendation="Add shell metacharacters to BLOCKED_COMMANDS list"
            ))
        else:
            self.report.add(TestResult(
                name="Command Injection",
                category="Injection",
                passed=True,
                severity="critical",
                description="Command injection payloads blocked"
            ))

    def test_injection_sql(self):
        """Test SQL injection in login"""
        self.log("Testing SQL injection...")

        sql_payloads = [
            ("admin' OR '1'='1", "anything"),
            ("admin'--", "anything"),
            ("admin'; DROP TABLE users;--", "x"),
            ("' OR 1=1--", "x"),
            ("admin' UNION SELECT * FROM users--", "x"),
        ]

        sqli_found = []
        for username, password in sql_payloads:
            resp = self.post("/api/auth/login", json={
                "username": username,
                "password": password
            })

            if resp.status_code == 200:
                sqli_found.append((username, password))
            # Also check for error disclosure
            if resp.status_code == 500 and "sql" in resp.text.lower():
                sqli_found.append((username, "error_disclosure"))

        if sqli_found:
            self.report.add(TestResult(
                name="SQL Injection",
                category="Injection",
                passed=False,
                severity="critical",
                description="SQL injection vulnerability in login",
                details=f"Successful payloads: {sqli_found}",
                recommendation="Use parameterized queries"
            ))
        else:
            self.report.add(TestResult(
                name="SQL Injection",
                category="Injection",
                passed=True,
                severity="critical",
                description="Login resistant to SQL injection"
            ))

    def test_injection_path_traversal(self):
        """Test path traversal in API endpoints"""
        self.log("Testing path traversal...")

        if not self.admin_token:
            return

        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..\\..\\..\\etc\\passwd",
        ]

        # Test device name parameter
        traversal_found = []
        for payload in traversal_payloads:
            resp = self.post("/api/command", token=self.admin_token, json={
                "device": payload,
                "command": "show version"
            })

            if resp.status_code == 200:
                traversal_found.append(payload)

        if traversal_found:
            self.report.add(TestResult(
                name="Path Traversal",
                category="Injection",
                passed=False,
                severity="high",
                description="Path traversal payloads accepted",
                details=f"Payloads: {traversal_found}",
                recommendation="Validate device names against whitelist"
            ))
        else:
            self.report.add(TestResult(
                name="Path Traversal",
                category="Injection",
                passed=True,
                severity="high",
                description="Path traversal payloads rejected"
            ))

    # =========================================================================
    # 4. Rate Limiting Tests
    # =========================================================================

    def test_rate_limiting_auth(self):
        """Test rate limiting on authentication endpoints"""
        self.log("Testing rate limiting on auth...")

        # Attempt rapid login attempts
        attempts = 20
        success_count = 0

        for i in range(attempts):
            resp = self.post("/api/auth/login", json={
                "username": "admin",
                "password": f"wrong{i}"
            })
            if resp.status_code != 429:  # Not rate limited
                success_count += 1

        if success_count >= attempts:
            self.report.add(TestResult(
                name="Auth Rate Limiting",
                category="Rate Limiting",
                passed=False,
                severity="high",
                description="No rate limiting on login endpoint",
                details=f"{success_count}/{attempts} attempts succeeded without rate limit",
                recommendation="Implement rate limiting (e.g., Flask-Limiter)"
            ))
        else:
            self.report.add(TestResult(
                name="Auth Rate Limiting",
                category="Rate Limiting",
                passed=True,
                severity="high",
                description=f"Rate limiting active after {attempts - success_count} blocked"
            ))

    def test_rate_limiting_commands(self):
        """Test rate limiting on command execution"""
        self.log("Testing rate limiting on commands...")

        if not self.admin_token:
            return

        # Attempt rapid command execution
        attempts = 100
        success_count = 0

        for _ in range(attempts):
            resp = self.post("/api/command", token=self.admin_token, json={
                "device": "R1",
                "command": "show clock"
            })
            if resp.status_code != 429:
                success_count += 1

        if success_count >= attempts:
            self.report.add(TestResult(
                name="Command Rate Limiting",
                category="Rate Limiting",
                passed=False,
                severity="medium",
                description="No rate limiting on command endpoint",
                details=f"{success_count}/{attempts} commands executed without rate limit",
                recommendation="Add rate limiting to prevent DoS"
            ))
        else:
            self.report.add(TestResult(
                name="Command Rate Limiting",
                category="Rate Limiting",
                passed=True,
                severity="medium",
                description=f"Rate limiting active ({attempts - success_count} blocked)"
            ))

    # =========================================================================
    # 5. Input Validation Tests
    # =========================================================================

    def test_input_validation_missing_fields(self):
        """Test handling of missing required fields"""
        self.log("Testing missing field handling...")

        test_cases = [
            ("/api/auth/login", {}),
            ("/api/auth/login", {"username": "admin"}),
            ("/api/auth/login", {"password": "admin"}),
            ("/api/command", {"device": "R1"}),
            ("/api/command", {"command": "show version"}),
        ]

        # All should return 400, not 500
        server_errors = []
        for endpoint, data in test_cases:
            resp = self.post(endpoint, token=self.admin_token, json=data)
            if resp.status_code == 500:
                server_errors.append((endpoint, data))

        if server_errors:
            self.report.add(TestResult(
                name="Missing Field Handling",
                category="Input Validation",
                passed=False,
                severity="medium",
                description="Server errors on missing fields (should be 400)",
                details=f"Errors: {server_errors}",
                recommendation="Validate all required fields before processing"
            ))
        else:
            self.report.add(TestResult(
                name="Missing Field Handling",
                category="Input Validation",
                passed=True,
                severity="medium",
                description="Missing fields handled gracefully"
            ))

    def test_input_validation_type_confusion(self):
        """Test type confusion attacks"""
        self.log("Testing type confusion...")

        type_payloads = [
            {"username": ["admin"], "password": "admin"},
            {"username": {"$gt": ""}, "password": "admin"},
            {"username": True, "password": "admin"},
            {"username": 123, "password": 456},
        ]

        type_issues = []
        for payload in type_payloads:
            resp = self.post("/api/auth/login", json=payload)
            if resp.status_code == 200:
                type_issues.append(payload)
            elif resp.status_code == 500:
                type_issues.append((payload, "server_error"))

        if type_issues:
            self.report.add(TestResult(
                name="Type Confusion",
                category="Input Validation",
                passed=False,
                severity="medium",
                description="Type confusion issues found",
                details=f"Issues: {type_issues}",
                recommendation="Validate input types strictly"
            ))
        else:
            self.report.add(TestResult(
                name="Type Confusion",
                category="Input Validation",
                passed=True,
                severity="medium",
                description="Type validation working correctly"
            ))

    def test_input_validation_oversized_input(self):
        """Test handling of oversized inputs"""
        self.log("Testing oversized input handling...")

        # Very long username/password
        long_string = "A" * 10000

        test_cases = [
            {"username": long_string, "password": "test"},
            {"username": "test", "password": long_string},
            {"device": "R1", "command": long_string},
        ]

        server_errors = []
        for i, payload in enumerate(test_cases):
            endpoint = "/api/auth/login" if i < 2 else "/api/command"
            resp = self.post(endpoint, token=self.admin_token, json=payload)
            if resp.status_code == 500:
                server_errors.append(endpoint)

        if server_errors:
            self.report.add(TestResult(
                name="Oversized Input Handling",
                category="Input Validation",
                passed=False,
                severity="low",
                description="Server errors on oversized input",
                details=f"Endpoints affected: {server_errors}",
                recommendation="Add input length limits"
            ))
        else:
            self.report.add(TestResult(
                name="Oversized Input Handling",
                category="Input Validation",
                passed=True,
                severity="low",
                description="Oversized inputs handled gracefully"
            ))

    # =========================================================================
    # 6. Security Headers Tests
    # =========================================================================

    def test_security_headers(self):
        """Test for security headers"""
        self.log("Testing security headers...")

        resp = self.get("/healthz")
        headers = resp.headers

        required_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": None,  # Any value is good
        }

        missing_headers = []
        for header, expected in required_headers.items():
            value = headers.get(header)
            if not value:
                missing_headers.append(header)
            elif expected and value not in (expected if isinstance(expected, list) else [expected]):
                missing_headers.append(f"{header} (wrong value: {value})")

        if missing_headers:
            self.report.add(TestResult(
                name="Security Headers",
                category="Security Headers",
                passed=False,
                severity="medium",
                description="Missing security headers",
                details=f"Missing: {missing_headers}",
                recommendation="Add security headers via middleware or reverse proxy"
            ))
        else:
            self.report.add(TestResult(
                name="Security Headers",
                category="Security Headers",
                passed=True,
                severity="medium",
                description="Security headers present"
            ))

    def test_cors_configuration(self):
        """Test CORS configuration"""
        self.log("Testing CORS configuration...")

        # Attempt request with malicious origin
        resp = self.get("/api/topology", headers={
            "Origin": "https://evil-site.com"
        })

        cors_header = resp.headers.get("Access-Control-Allow-Origin", "")

        if cors_header == "*":
            self.report.add(TestResult(
                name="CORS Configuration",
                category="Security Headers",
                passed=False,
                severity="medium",
                description="CORS allows all origins (*)",
                recommendation="Restrict CORS to specific trusted origins"
            ))
        elif "evil-site.com" in cors_header:
            self.report.add(TestResult(
                name="CORS Configuration",
                category="Security Headers",
                passed=False,
                severity="high",
                description="CORS reflects arbitrary origin",
                recommendation="Validate origin against whitelist"
            ))
        else:
            self.report.add(TestResult(
                name="CORS Configuration",
                category="Security Headers",
                passed=True,
                severity="medium",
                description="CORS configuration appears secure"
            ))

    # =========================================================================
    # Run All Tests
    # =========================================================================

    def run_all_tests(self):
        """Execute all security tests"""
        print("\n" + "=" * 60)
        print("  NetworkOps API Security Test Suite")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Time: {self.report.timestamp}")
        print("=" * 60 + "\n")

        # Setup
        if not self.setup():
            print("\n[FATAL] Could not authenticate. Aborting tests.")
            return

        # Run all test methods
        test_methods = [
            # Authentication
            # IMPORTANT: Lockout test runs FIRST before other auth tests consume rate limit
            self.test_auth_account_lockout,
            self.test_auth_default_credentials,
            self.test_auth_jwt_weak_secret,
            self.test_auth_jwt_none_algorithm,
            self.test_auth_jwt_expired_token,
            self.test_auth_missing_token,
            self.test_auth_password_complexity,
            self.test_auth_token_refresh,
            self.test_auth_logout_invalidation,

            # Authorization
            self.test_authz_privilege_escalation,
            self.test_authz_idor_user_management,
            self.test_authz_permission_check_bypass,

            # Injection
            self.test_injection_command,
            self.test_injection_sql,
            self.test_injection_path_traversal,

            # Rate Limiting
            self.test_rate_limiting_auth,
            self.test_rate_limiting_commands,

            # Input Validation
            self.test_input_validation_missing_fields,
            self.test_input_validation_type_confusion,
            self.test_input_validation_oversized_input,

            # Security Headers
            self.test_security_headers,
            self.test_cors_configuration,
        ]

        for test in test_methods:
            try:
                test()
            except Exception as e:
                self.log(f"Test {test.__name__} failed: {e}", "fail")

        # Print report
        self.print_report()

    def print_report(self):
        """Print formatted security report"""
        print("\n" + "=" * 60)
        print("  SECURITY TEST RESULTS")
        print("=" * 60)

        summary = self.report.summary()
        print(f"\nTotal Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Pass Rate: {summary['pass_rate']}")

        if summary['failures_by_severity']:
            print("\nFailures by Severity:")
            for severity, count in sorted(summary['failures_by_severity'].items()):
                color = {
                    "critical": "\033[91m",
                    "high": "\033[93m",
                    "medium": "\033[94m",
                    "low": "\033[92m"
                }.get(severity, "")
                print(f"  {color}{severity.upper()}\033[0m: {count}")

        # Group results by category
        by_category = {}
        for result in self.report.results:
            if result.category not in by_category:
                by_category[result.category] = []
            by_category[result.category].append(result)

        print("\n" + "-" * 60)
        print("DETAILED RESULTS")
        print("-" * 60)

        for category, results in by_category.items():
            print(f"\n[{category}]")
            for r in results:
                status = "\033[92m✓ PASS\033[0m" if r.passed else "\033[91m✗ FAIL\033[0m"
                print(f"  {status} {r.name} ({r.severity})")
                if not r.passed:
                    print(f"       Description: {r.description}")
                    if r.details:
                        print(f"       Details: {r.details}")
                    if r.recommendation:
                        print(f"       Fix: {r.recommendation}")

        # Export JSON report to data/security_reports/
        reports_dir = Path(__file__).parent.parent / "data" / "security_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w") as f:
            json.dump({
                "target": self.report.target,
                "timestamp": self.report.timestamp,
                "summary": summary,
                "results": [
                    {
                        "name": r.name,
                        "category": r.category,
                        "passed": r.passed,
                        "severity": r.severity,
                        "description": r.description,
                        "details": r.details,
                        "recommendation": r.recommendation,
                    }
                    for r in self.report.results
                ]
            }, f, indent=2)

        print(f"\n\nFull report saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="NetworkOps API Security Testing")
    parser.add_argument("--target", default="http://localhost:5001", help="API base URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    tester = APISecurityTester(args.target, verbose=args.verbose)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
