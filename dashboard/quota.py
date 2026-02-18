"""
Token Quota Management Module

Provides organization-based token quotas for the chat API:
- Token usage tracking (input + output)
- Monthly quota enforcement with hard blocking
- Organization management for multi-tenant support
"""

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

from core.db import DatabaseManager

# =============================================================================
# Configuration
# =============================================================================

# Default quota (1M tokens per month)
DEFAULT_MONTHLY_TOKEN_LIMIT = int(os.getenv("CHAT_MONTHLY_TOKEN_QUOTA", "1000000"))

# Enable/disable quota enforcement
QUOTA_ENFORCEMENT_ENABLED = os.getenv("QUOTA_ENFORCEMENT_ENABLED", "true").lower() == "true"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class QuotaStatus:
    """Result of a quota check"""
    allowed: bool
    used: int
    limit: int
    remaining: int
    billing_period: str
    message: str = ""
    reset_date: str = ""


@dataclass
class UsageRecord:
    """Token usage from a single request"""
    input_tokens: int
    output_tokens: int
    model: str = "claude-3-5-sonnet-20241022"


# =============================================================================
# Database Helpers
# =============================================================================

def _get_db_connection():
    """Get database connection from the consolidated pool."""
    return DatabaseManager.get_instance().get_connection()


def _get_current_billing_period() -> str:
    """Get current billing period in YYYY-MM format"""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _get_next_reset_date() -> str:
    """Get the first day of next month as reset date"""
    now = datetime.now(timezone.utc)
    if now.month == 12:
        return f"{now.year + 1}-01-01"
    return f"{now.year}-{now.month + 1:02d}-01"


# =============================================================================
# Organization Functions
# =============================================================================

def create_organization(name: str, slug: str, monthly_limit: int = None) -> tuple[bool, str, int | None]:
    """
    Create a new organization with default quota.

    Args:
        name: Organization display name
        slug: URL-friendly unique identifier
        monthly_limit: Optional custom monthly token limit

    Returns:
        (success, message, org_id)
    """
    if not name or not slug:
        return False, "Name and slug are required", None

    limit = monthly_limit or DEFAULT_MONTHLY_TOKEN_LIMIT

    try:
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Create organization
        cursor.execute(
            "INSERT INTO organizations (name, slug) VALUES (?, ?)",
            (name, slug)
        )
        org_id = cursor.lastrowid

        # Create quota record
        cursor.execute(
            "INSERT INTO organization_quotas (organization_id, monthly_token_limit) VALUES (?, ?)",
            (org_id, limit)
        )

        conn.commit()
        conn.close()
        return True, f"Organization '{name}' created", org_id
    except sqlite3.IntegrityError:
        return False, f"Organization with name or slug already exists", None
    except Exception as e:
        return False, f"Failed to create organization: {e}", None


def get_organization(org_id: int) -> dict | None:
    """Get organization by ID"""
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, slug, is_active, created_at FROM organizations WHERE id = ?",
        (org_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "id": row["id"],
            "name": row["name"],
            "slug": row["slug"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }
    return None


def get_organization_by_slug(slug: str) -> dict | None:
    """Get organization by slug"""
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, slug, is_active, created_at FROM organizations WHERE slug = ?",
        (slug,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "id": row["id"],
            "name": row["name"],
            "slug": row["slug"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
        }
    return None


def list_organizations() -> list[dict]:
    """List all organizations with their quotas"""
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT o.id, o.name, o.slug, o.is_active, o.created_at,
               COALESCE(q.monthly_token_limit, ?) as monthly_token_limit
        FROM organizations o
        LEFT JOIN organization_quotas q ON o.id = q.organization_id
        ORDER BY o.name
    """, (DEFAULT_MONTHLY_TOKEN_LIMIT,))

    orgs = []
    for row in cursor.fetchall():
        orgs.append({
            "id": row["id"],
            "name": row["name"],
            "slug": row["slug"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "monthly_token_limit": row["monthly_token_limit"],
        })
    conn.close()
    return orgs


# =============================================================================
# User-Organization Mapping
# =============================================================================

def get_organization_for_user(user_id: int) -> int | None:
    """
    Get the organization ID for a user.

    Args:
        user_id: User's database ID

    Returns:
        Organization ID or None if user has no organization
    """
    if not user_id:
        return None

    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT organization_id FROM user_organizations WHERE user_id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()

    return row["organization_id"] if row else None


def assign_user_to_organization(user_id: int, org_id: int, role: str = "member") -> tuple[bool, str]:
    """
    Assign a user to an organization.

    Args:
        user_id: User's database ID
        org_id: Organization ID
        role: Role within organization (member, admin, owner)

    Returns:
        (success, message)
    """
    if not user_id or not org_id:
        return False, "User ID and Organization ID are required"

    try:
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Check org exists
        cursor.execute("SELECT id FROM organizations WHERE id = ?", (org_id,))
        if not cursor.fetchone():
            conn.close()
            return False, "Organization not found"

        # Upsert user-organization mapping
        cursor.execute("""
            INSERT INTO user_organizations (user_id, organization_id, role)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                organization_id = excluded.organization_id,
                role = excluded.role
        """, (user_id, org_id, role))

        conn.commit()
        conn.close()
        return True, "User assigned to organization"
    except Exception as e:
        return False, f"Failed to assign user: {e}"


def get_organization_users(org_id: int) -> list[dict]:
    """Get all users in an organization"""
    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.role as user_role, uo.role as org_role, uo.created_at
        FROM users u
        JOIN user_organizations uo ON u.id = uo.user_id
        WHERE uo.organization_id = ?
        ORDER BY u.username
    """, (org_id,))

    users = []
    for row in cursor.fetchall():
        users.append({
            "id": row["id"],
            "username": row["username"],
            "user_role": row["user_role"],
            "org_role": row["org_role"],
            "joined_at": row["created_at"],
        })
    conn.close()
    return users


# =============================================================================
# Quota Check and Enforcement
# =============================================================================

def check_quota(org_id: int) -> QuotaStatus:
    """
    Check if organization has remaining quota.

    Args:
        org_id: Organization ID

    Returns:
        QuotaStatus with allowed flag and usage details
    """
    # Quota enforcement disabled - always allow
    if not QUOTA_ENFORCEMENT_ENABLED:
        return QuotaStatus(
            allowed=True,
            used=0,
            limit=0,
            remaining=0,
            billing_period=_get_current_billing_period(),
            message="Quota enforcement disabled"
        )

    # No org - allow with default quota (for anonymous/unassigned users)
    if not org_id:
        return QuotaStatus(
            allowed=True,
            used=0,
            limit=DEFAULT_MONTHLY_TOKEN_LIMIT,
            remaining=DEFAULT_MONTHLY_TOKEN_LIMIT,
            billing_period=_get_current_billing_period(),
            message="No organization assigned"
        )

    conn = _get_db_connection()
    cursor = conn.cursor()
    billing_period = _get_current_billing_period()

    # Get quota limit
    cursor.execute(
        "SELECT monthly_token_limit FROM organization_quotas WHERE organization_id = ?",
        (org_id,)
    )
    quota_row = cursor.fetchone()
    limit = quota_row["monthly_token_limit"] if quota_row else DEFAULT_MONTHLY_TOKEN_LIMIT

    # Get current usage from summary table
    cursor.execute(
        "SELECT total_tokens FROM monthly_usage_summary WHERE organization_id = ? AND billing_period = ?",
        (org_id, billing_period)
    )
    usage_row = cursor.fetchone()
    used = usage_row["total_tokens"] if usage_row else 0

    conn.close()

    remaining = max(0, limit - used)
    allowed = used < limit

    return QuotaStatus(
        allowed=allowed,
        used=used,
        limit=limit,
        remaining=remaining,
        billing_period=billing_period,
        reset_date=_get_next_reset_date(),
        message="" if allowed else f"Monthly token limit reached. Resets {_get_next_reset_date()}."
    )


def get_quota_limit(org_id: int) -> int:
    """Get the monthly token limit for an organization"""
    if not org_id:
        return DEFAULT_MONTHLY_TOKEN_LIMIT

    conn = _get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT monthly_token_limit FROM organization_quotas WHERE organization_id = ?",
        (org_id,)
    )
    row = cursor.fetchone()
    conn.close()

    return row["monthly_token_limit"] if row else DEFAULT_MONTHLY_TOKEN_LIMIT


def update_quota(org_id: int, monthly_limit: int) -> tuple[bool, str]:
    """
    Update the monthly token limit for an organization.

    Args:
        org_id: Organization ID
        monthly_limit: New monthly token limit

    Returns:
        (success, message)
    """
    if not org_id:
        return False, "Organization ID is required"

    if monthly_limit < 0:
        return False, "Monthly limit cannot be negative"

    try:
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Upsert quota
        cursor.execute("""
            INSERT INTO organization_quotas (organization_id, monthly_token_limit, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(organization_id) DO UPDATE SET
                monthly_token_limit = excluded.monthly_token_limit,
                updated_at = CURRENT_TIMESTAMP
        """, (org_id, monthly_limit))

        conn.commit()
        conn.close()
        return True, f"Quota updated to {monthly_limit:,} tokens/month"
    except Exception as e:
        return False, f"Failed to update quota: {e}"


# =============================================================================
# Usage Recording
# =============================================================================

def record_usage(org_id: int, user_id: int, usage: UsageRecord) -> tuple[bool, str]:
    """
    Record token usage from a chat request.

    Args:
        org_id: Organization ID
        user_id: User ID who made the request
        usage: UsageRecord with input/output tokens

    Returns:
        (success, message)
    """
    if not org_id or not user_id:
        return False, "Organization and user ID are required"

    total_tokens = usage.input_tokens + usage.output_tokens
    billing_period = _get_current_billing_period()

    try:
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Record individual usage
        cursor.execute("""
            INSERT INTO token_usage (organization_id, user_id, model, input_tokens, output_tokens, billing_period)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (org_id, user_id, usage.model, usage.input_tokens, usage.output_tokens, billing_period))

        # Update summary table (upsert)
        cursor.execute("""
            INSERT INTO monthly_usage_summary (organization_id, billing_period, total_tokens, request_count, last_updated)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(organization_id, billing_period) DO UPDATE SET
                total_tokens = monthly_usage_summary.total_tokens + excluded.total_tokens,
                request_count = monthly_usage_summary.request_count + 1,
                last_updated = CURRENT_TIMESTAMP
        """, (org_id, billing_period, total_tokens))

        conn.commit()
        conn.close()
        return True, f"Recorded {total_tokens:,} tokens"
    except Exception as e:
        return False, f"Failed to record usage: {e}"


# =============================================================================
# Usage Reporting
# =============================================================================

def get_usage_summary(org_id: int, billing_period: str = None) -> dict:
    """
    Get usage summary for an organization.

    Args:
        org_id: Organization ID
        billing_period: Optional billing period (defaults to current)

    Returns:
        Dict with usage stats
    """
    if not org_id:
        return {
            "organization_id": None,
            "billing_period": _get_current_billing_period(),
            "total_tokens": 0,
            "request_count": 0,
            "limit": DEFAULT_MONTHLY_TOKEN_LIMIT,
            "remaining": DEFAULT_MONTHLY_TOKEN_LIMIT,
            "usage_percent": 0.0,
        }

    billing_period = billing_period or _get_current_billing_period()

    conn = _get_db_connection()
    cursor = conn.cursor()

    # Get usage summary
    cursor.execute(
        "SELECT total_tokens, request_count FROM monthly_usage_summary WHERE organization_id = ? AND billing_period = ?",
        (org_id, billing_period)
    )
    usage_row = cursor.fetchone()

    # Get quota limit
    cursor.execute(
        "SELECT monthly_token_limit FROM organization_quotas WHERE organization_id = ?",
        (org_id,)
    )
    quota_row = cursor.fetchone()

    conn.close()

    total_tokens = usage_row["total_tokens"] if usage_row else 0
    request_count = usage_row["request_count"] if usage_row else 0
    limit = quota_row["monthly_token_limit"] if quota_row else DEFAULT_MONTHLY_TOKEN_LIMIT
    remaining = max(0, limit - total_tokens)
    usage_percent = (total_tokens / limit * 100) if limit > 0 else 0.0

    return {
        "organization_id": org_id,
        "billing_period": billing_period,
        "total_tokens": total_tokens,
        "request_count": request_count,
        "limit": limit,
        "remaining": remaining,
        "usage_percent": round(usage_percent, 2),
        "reset_date": _get_next_reset_date(),
    }


def get_user_usage(user_id: int, billing_period: str = None) -> dict:
    """
    Get usage breakdown for a specific user.

    Args:
        user_id: User ID
        billing_period: Optional billing period (defaults to current)

    Returns:
        Dict with user's usage stats
    """
    billing_period = billing_period or _get_current_billing_period()

    conn = _get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            SUM(input_tokens) as total_input,
            SUM(output_tokens) as total_output,
            COUNT(*) as request_count
        FROM token_usage
        WHERE user_id = ? AND billing_period = ?
    """, (user_id, billing_period))

    row = cursor.fetchone()
    conn.close()

    total_input = row["total_input"] or 0
    total_output = row["total_output"] or 0

    return {
        "user_id": user_id,
        "billing_period": billing_period,
        "input_tokens": total_input,
        "output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "request_count": row["request_count"] or 0,
    }


def get_usage_history(org_id: int, months: int = 6) -> list[dict]:
    """
    Get historical usage for an organization.

    Args:
        org_id: Organization ID
        months: Number of months of history

    Returns:
        List of monthly usage records
    """
    conn = _get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT billing_period, total_tokens, request_count, last_updated
        FROM monthly_usage_summary
        WHERE organization_id = ?
        ORDER BY billing_period DESC
        LIMIT ?
    """, (org_id, months))

    history = []
    for row in cursor.fetchall():
        history.append({
            "billing_period": row["billing_period"],
            "total_tokens": row["total_tokens"],
            "request_count": row["request_count"],
            "last_updated": row["last_updated"],
        })

    conn.close()
    return history


# =============================================================================
# Admin Functions
# =============================================================================

def get_all_quotas() -> list[dict]:
    """Get quota status for all organizations (admin view)"""
    billing_period = _get_current_billing_period()

    conn = _get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            o.id, o.name, o.slug,
            COALESCE(q.monthly_token_limit, ?) as monthly_limit,
            COALESCE(s.total_tokens, 0) as used_tokens,
            COALESCE(s.request_count, 0) as request_count
        FROM organizations o
        LEFT JOIN organization_quotas q ON o.id = q.organization_id
        LEFT JOIN monthly_usage_summary s ON o.id = s.organization_id AND s.billing_period = ?
        WHERE o.is_active = 1
        ORDER BY o.name
    """, (DEFAULT_MONTHLY_TOKEN_LIMIT, billing_period))

    quotas = []
    for row in cursor.fetchall():
        limit = row["monthly_limit"]
        used = row["used_tokens"]
        remaining = max(0, limit - used)
        usage_percent = (used / limit * 100) if limit > 0 else 0.0

        quotas.append({
            "organization_id": row["id"],
            "organization_name": row["name"],
            "organization_slug": row["slug"],
            "monthly_limit": limit,
            "used_tokens": used,
            "remaining_tokens": remaining,
            "request_count": row["request_count"],
            "usage_percent": round(usage_percent, 2),
            "billing_period": billing_period,
        })

    conn.close()
    return quotas


def reset_usage(org_id: int, billing_period: str = None) -> tuple[bool, str]:
    """
    Reset usage for an organization (admin only).

    Args:
        org_id: Organization ID
        billing_period: Optional specific period to reset (defaults to current)

    Returns:
        (success, message)
    """
    billing_period = billing_period or _get_current_billing_period()

    try:
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Delete usage records
        cursor.execute(
            "DELETE FROM token_usage WHERE organization_id = ? AND billing_period = ?",
            (org_id, billing_period)
        )

        # Reset summary
        cursor.execute(
            "DELETE FROM monthly_usage_summary WHERE organization_id = ? AND billing_period = ?",
            (org_id, billing_period)
        )

        conn.commit()
        conn.close()
        return True, f"Usage reset for period {billing_period}"
    except Exception as e:
        return False, f"Failed to reset usage: {e}"
