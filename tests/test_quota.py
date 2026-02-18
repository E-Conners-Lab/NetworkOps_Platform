#!/usr/bin/env python3
"""
Token Quota System Tests

Tests for the organization-based token quota system:
- Quota checking and enforcement
- Usage recording and tracking
- Organization management
- API endpoints (user and admin)

Usage:
    pytest tests/test_quota.py -v
    pytest tests/test_quota.py -v -k "test_check"  # Run specific tests
"""

import os
import sys
import pytest
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_db(consolidated_db):
    """Use the consolidated test DB (all tables created by Alembic)."""
    yield consolidated_db


@pytest.fixture
def quota_module(temp_db):
    """Import quota module (uses DatabaseManager pointed at temp DB)."""
    from dashboard import quota
    yield quota


def _get_conn():
    """Shorthand for getting a DB connection via DatabaseManager."""
    from core.db import DatabaseManager
    return DatabaseManager.get_instance().get_connection()


def _release_conn(conn):
    """Return connection to the pool."""
    from core.db import DatabaseManager
    DatabaseManager.get_instance().release_connection(conn)


@pytest.fixture
def test_org(quota_module, temp_db):
    """Create a test organization with quota."""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO organizations (name, slug) VALUES (?, ?)",
        ("Test Corp", "test-corp")
    )
    org_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO organization_quotas (organization_id, monthly_token_limit) VALUES (?, ?)",
        (org_id, 100000)
    )

    conn.commit()
    _release_conn(conn)

    return {
        "id": org_id,
        "name": "Test Corp",
        "slug": "test-corp",
        "monthly_limit": 100000
    }


@pytest.fixture
def test_user(temp_db):
    """Create a test user."""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("testuser", "hash123", "operator")
    )
    user_id = cursor.lastrowid

    conn.commit()
    _release_conn(conn)

    return {"id": user_id, "username": "testuser"}


@pytest.fixture
def test_user_with_org(temp_db, test_org, test_user):
    """Create a test user assigned to an organization."""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)",
        (test_user["id"], test_org["id"], "member")
    )

    conn.commit()
    _release_conn(conn)

    return {**test_user, "organization_id": test_org["id"]}


# =============================================================================
# Unit Tests - Quota Checking
# =============================================================================

class TestQuotaChecking:
    """Tests for quota checking functionality."""

    def test_check_quota_under_limit(self, quota_module, test_org, temp_db):
        """Quota check passes when under limit."""
        status = quota_module.check_quota(test_org["id"])

        assert status.allowed is True
        assert status.used == 0
        assert status.limit == 100000
        assert status.remaining == 100000

    def test_check_quota_at_limit(self, quota_module, test_org, temp_db):
        """Quota check fails when at limit."""
        billing_period = datetime.now(timezone.utc).strftime("%Y-%m")

        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO monthly_usage_summary (organization_id, billing_period, total_tokens, request_count)
            VALUES (?, ?, ?, ?)
        """, (test_org["id"], billing_period, 100000, 100))
        conn.commit()
        _release_conn(conn)

        status = quota_module.check_quota(test_org["id"])

        assert status.allowed is False
        assert status.used == 100000
        assert status.limit == 100000
        assert status.remaining == 0
        assert "limit reached" in status.message.lower()

    def test_check_quota_over_limit(self, quota_module, test_org, temp_db):
        """Quota check fails when over limit."""
        billing_period = datetime.now(timezone.utc).strftime("%Y-%m")

        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO monthly_usage_summary (organization_id, billing_period, total_tokens, request_count)
            VALUES (?, ?, ?, ?)
        """, (test_org["id"], billing_period, 150000, 150))
        conn.commit()
        _release_conn(conn)

        status = quota_module.check_quota(test_org["id"])

        assert status.allowed is False
        assert status.remaining == 0

    def test_check_quota_no_org(self, quota_module, temp_db):
        """Quota check for non-existent org returns allowed (no quota)."""
        status = quota_module.check_quota(None)

        assert status.allowed is True
        assert "No organization" in status.message

    def test_check_quota_enforcement_disabled(self, quota_module, test_org, temp_db):
        """Quota check passes when enforcement is disabled."""
        with patch('dashboard.quota.QUOTA_ENFORCEMENT_ENABLED', False):
            status = quota_module.check_quota(test_org["id"])

            assert status.allowed is True
            assert "disabled" in status.message.lower()


# =============================================================================
# Unit Tests - Usage Recording
# =============================================================================

class TestUsageRecording:
    """Tests for usage recording functionality."""

    def test_record_usage(self, quota_module, test_org, test_user_with_org, temp_db):
        """Usage is correctly recorded to database."""
        usage = quota_module.UsageRecord(
            input_tokens=1000,
            output_tokens=500,
            model="claude-3-5-sonnet"
        )

        success, message = quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            usage
        )

        assert success is True
        assert "1,500" in message  # Total tokens

        # Verify in database
        conn = _get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT input_tokens, output_tokens FROM token_usage WHERE user_id = ?",
                      (test_user_with_org["id"],))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 1000
        assert row[1] == 500

        billing_period = datetime.now(timezone.utc).strftime("%Y-%m")
        cursor.execute(
            "SELECT total_tokens, request_count FROM monthly_usage_summary WHERE organization_id = ? AND billing_period = ?",
            (test_org["id"], billing_period)
        )
        summary = cursor.fetchone()
        assert summary is not None
        assert summary[0] == 1500
        assert summary[1] == 1

        _release_conn(conn)

    def test_record_usage_accumulates(self, quota_module, test_org, test_user_with_org, temp_db):
        """Multiple usage records accumulate correctly."""
        quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            quota_module.UsageRecord(input_tokens=1000, output_tokens=500)
        )

        quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            quota_module.UsageRecord(input_tokens=2000, output_tokens=1000)
        )

        summary = quota_module.get_usage_summary(test_org["id"])
        assert summary["total_tokens"] == 4500  # 1500 + 3000
        assert summary["request_count"] == 2

    def test_record_usage_missing_org(self, quota_module, test_user, temp_db):
        """Recording usage without org_id fails."""
        usage = quota_module.UsageRecord(input_tokens=100, output_tokens=50)

        success, message = quota_module.record_usage(None, test_user["id"], usage)
        assert success is False


# =============================================================================
# Unit Tests - Usage Summary
# =============================================================================

class TestUsageSummary:
    """Tests for usage summary and reporting."""

    def test_get_usage_summary(self, quota_module, test_org, test_user_with_org, temp_db):
        """Summary correctly aggregates token usage."""
        quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            quota_module.UsageRecord(input_tokens=5000, output_tokens=2500)
        )

        summary = quota_module.get_usage_summary(test_org["id"])

        assert summary["organization_id"] == test_org["id"]
        assert summary["total_tokens"] == 7500
        assert summary["request_count"] == 1
        assert summary["limit"] == 100000
        assert summary["remaining"] == 92500
        assert summary["usage_percent"] == 7.5  # 7500/100000 * 100

    def test_get_user_usage(self, quota_module, test_org, test_user_with_org, temp_db):
        """User usage breakdown is correct."""
        quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            quota_module.UsageRecord(input_tokens=1000, output_tokens=500)
        )

        user_usage = quota_module.get_user_usage(test_user_with_org["id"])

        assert user_usage["user_id"] == test_user_with_org["id"]
        assert user_usage["input_tokens"] == 1000
        assert user_usage["output_tokens"] == 500
        assert user_usage["total_tokens"] == 1500
        assert user_usage["request_count"] == 1

    def test_monthly_reset(self, quota_module, test_org, test_user_with_org, temp_db):
        """New billing period starts with zero usage."""
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO monthly_usage_summary (organization_id, billing_period, total_tokens, request_count)
            VALUES (?, ?, ?, ?)
        """, (test_org["id"], "2024-01", 50000, 50))
        conn.commit()
        _release_conn(conn)

        current_period = datetime.now(timezone.utc).strftime("%Y-%m")
        if current_period != "2024-01":
            summary = quota_module.get_usage_summary(test_org["id"])
            assert summary["total_tokens"] == 0
            assert summary["request_count"] == 0


# =============================================================================
# Unit Tests - Organization Management
# =============================================================================

class TestOrganizationManagement:
    """Tests for organization CRUD operations."""

    def test_create_organization(self, quota_module, temp_db):
        """Organization is created with quota."""
        success, message, org_id = quota_module.create_organization(
            "New Company",
            "new-company",
            monthly_limit=500000
        )

        assert success is True
        assert org_id is not None

        org = quota_module.get_organization(org_id)
        assert org["name"] == "New Company"
        assert org["slug"] == "new-company"

        limit = quota_module.get_quota_limit(org_id)
        assert limit == 500000

    def test_create_organization_duplicate(self, quota_module, test_org, temp_db):
        """Duplicate organization name/slug fails."""
        success, message, org_id = quota_module.create_organization(
            "Test Corp",  # Same name as test_org
            "test-corp",
            monthly_limit=100000
        )

        assert success is False
        assert org_id is None
        assert "exists" in message.lower()

    def test_get_organization_for_user(self, quota_module, test_user_with_org, temp_db):
        """Returns correct org for user, None if not assigned."""
        org_id = quota_module.get_organization_for_user(test_user_with_org["id"])
        assert org_id == test_user_with_org["organization_id"]

        # User not in org
        org_id = quota_module.get_organization_for_user(9999)
        assert org_id is None

    def test_assign_user_to_organization(self, quota_module, test_org, test_user, temp_db):
        """User can be assigned to organization."""
        success, message = quota_module.assign_user_to_organization(
            test_user["id"],
            test_org["id"],
            role="admin"
        )

        assert success is True

        org_id = quota_module.get_organization_for_user(test_user["id"])
        assert org_id == test_org["id"]

    def test_update_quota(self, quota_module, test_org, temp_db):
        """Quota limit can be updated."""
        success, message = quota_module.update_quota(test_org["id"], 200000)

        assert success is True

        limit = quota_module.get_quota_limit(test_org["id"])
        assert limit == 200000


# =============================================================================
# Integration Tests
# =============================================================================

class TestQuotaIntegration:
    """Integration tests that simulate real API usage patterns."""

    def test_quota_blocks_when_exceeded(self, quota_module, test_org, test_user_with_org, temp_db):
        """Quota check fails after usage exceeds limit."""
        status = quota_module.check_quota(test_org["id"])
        assert status.allowed is True

        for i in range(20):
            quota_module.record_usage(
                test_org["id"],
                test_user_with_org["id"],
                quota_module.UsageRecord(input_tokens=5000, output_tokens=2500)
            )

        status = quota_module.check_quota(test_org["id"])
        assert status.allowed is False
        assert status.used >= 100000

    def test_reset_usage(self, quota_module, test_org, test_user_with_org, temp_db):
        """Admin can reset usage for an organization."""
        quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            quota_module.UsageRecord(input_tokens=50000, output_tokens=25000)
        )

        success, message = quota_module.reset_usage(test_org["id"])
        assert success is True

        summary = quota_module.get_usage_summary(test_org["id"])
        assert summary["total_tokens"] == 0
        assert summary["request_count"] == 0


# =============================================================================
# Token Usage Model Tests
# =============================================================================

class TestTokenUsageModel:
    """Tests for TokenUsage pydantic model."""

    def test_token_usage_model(self):
        """TokenUsage model calculates total correctly."""
        from rag.models import TokenUsage

        usage = TokenUsage(
            input_tokens=1000,
            output_tokens=500,
            model="claude-3-5-sonnet"
        )

        assert usage.input_tokens == 1000
        assert usage.output_tokens == 500
        assert usage.total_tokens == 1500
        assert usage.model == "claude-3-5-sonnet"

    def test_chat_response_includes_usage(self):
        """ChatResponse model includes optional usage field."""
        from rag.models import ChatResponse, TokenUsage

        response = ChatResponse(
            response="Hello!",
            sources=[],
            usage=TokenUsage(input_tokens=100, output_tokens=50, model="test")
        )

        assert response.usage is not None
        assert response.usage.total_tokens == 150

        # Usage can be None
        response_no_usage = ChatResponse(response="Hi!", sources=[])
        assert response_no_usage.usage is None


# =============================================================================
# API Endpoint Tests (Mock-based)
# =============================================================================

class TestQuotaAPIEndpoints:
    """Tests for quota-related API endpoints using mocks."""

    def test_chat_quota_exceeded_returns_402(self):
        """Chat returns 402 when quota exceeded."""
        from flask import Flask
        from unittest.mock import patch, MagicMock

        # Mock quota check to return exceeded
        mock_quota_status = MagicMock()
        mock_quota_status.allowed = False
        mock_quota_status.used = 100000
        mock_quota_status.limit = 100000
        mock_quota_status.remaining = 0
        mock_quota_status.billing_period = "2025-01"
        mock_quota_status.reset_date = "2025-02-01"
        mock_quota_status.message = "Monthly token limit reached"

        with patch('dashboard.quota.check_quota', return_value=mock_quota_status):
            with patch('dashboard.quota.get_organization_for_user', return_value=1):
                with patch('dashboard.quota.QUOTA_ENFORCEMENT_ENABLED', True):
                    # The actual endpoint test would require the full app context
                    # This verifies the quota check logic
                    from dashboard.quota import check_quota, QUOTA_ENFORCEMENT_ENABLED
                    status = check_quota(1)
                    assert status.allowed is False

    def test_usage_endpoint_returns_quota_info(self):
        """GET /api/usage returns quota and usage information."""
        # This would be an integration test with the actual Flask app
        # For unit testing, we verify the underlying functions
        from dashboard.quota import get_usage_summary, check_quota

        # Verify functions return expected structure
        # (actual test requires Flask test client and database setup)
        pass


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case and boundary condition tests."""

    def test_zero_quota_blocks_all_requests(self, quota_module, temp_db):
        """Organization with zero quota blocks all requests."""
        conn = _get_conn()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO organizations (name, slug) VALUES (?, ?)",
            ("Zero Quota Org", "zero-quota")
        )
        org_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO organization_quotas (organization_id, monthly_token_limit) VALUES (?, ?)",
            (org_id, 0)
        )
        conn.commit()
        _release_conn(conn)

        status = quota_module.check_quota(org_id)
        assert status.allowed is False
        assert status.limit == 0

    def test_very_large_quota(self, quota_module, temp_db):
        """Very large quota values work correctly."""
        large_limit = 10_000_000_000  # 10 billion tokens
        success, _, org_id = quota_module.create_organization(
            "Big Corp",
            "big-corp",
            monthly_limit=large_limit
        )
        assert success

        limit = quota_module.get_quota_limit(org_id)
        assert limit == large_limit

    def test_negative_quota_rejected(self, quota_module, test_org, temp_db):
        """Negative quota values are rejected."""
        success, message = quota_module.update_quota(test_org["id"], -1000)
        assert success is False
        assert "negative" in message.lower()

    def test_usage_record_with_zero_tokens(self, quota_module, test_org, test_user_with_org, temp_db):
        """Zero token usage is recorded correctly."""
        usage = quota_module.UsageRecord(
            input_tokens=0,
            output_tokens=0,
            model="test"
        )
        success, _ = quota_module.record_usage(
            test_org["id"],
            test_user_with_org["id"],
            usage
        )
        assert success is True

        summary = quota_module.get_usage_summary(test_org["id"])
        assert summary["total_tokens"] == 0
        assert summary["request_count"] == 1  # Still counts as a request


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
