"""
Password hashing, verification, validation, and account lockout.

Handles:
- Password hashing (bcrypt via werkzeug)
- Password verification
- Password strength validation
- Account lockout after failed attempts
"""
import re
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from .config import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGIT,
    PASSWORD_REQUIRE_SPECIAL,
    LOCKOUT_THRESHOLD,
    LOCKOUT_DURATION_MINUTES,
)
from . import database

# Re-export werkzeug functions for convenience
__all__ = [
    "hash_password",
    "verify_password",
    "validate_password_strength",
    "is_account_locked",
    "record_failed_attempt",
    "clear_lockout",
]


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Bcrypt hash of the password
    """
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash.

    Args:
        password: Plain text password
        password_hash: Bcrypt hash to check against

    Returns:
        True if password matches, False otherwise
    """
    return check_password_hash(password_hash, password)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets complexity requirements.

    OWASP A07:2021 - Password strength requirements.

    Args:
        password: Password to validate

    Returns:
        (is_valid, error_message) tuple
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"

    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        return False, "Password must contain at least one digit"

    if PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"

    return True, ""


# =============================================================================
# Account Lockout Functions
# =============================================================================

def is_account_locked(username: str) -> tuple[bool, int]:
    """Check if account is locked.

    Args:
        username: Username to check

    Returns:
        (is_locked, remaining_seconds) tuple
    """
    if not database.USE_SQLITE:
        return False, 0

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT locked_until FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row or not row["locked_until"]:
        return False, 0

    locked_until = datetime.fromisoformat(row["locked_until"])
    now = datetime.now(timezone.utc)

    if locked_until > now:
        remaining = int((locked_until - now).total_seconds())
        return True, remaining

    # Lockout expired, clear it
    clear_lockout(username)
    return False, 0


def record_failed_attempt(username: str) -> tuple[int, bool]:
    """Record a failed login attempt.

    Args:
        username: Username that failed to authenticate

    Returns:
        (attempt_count, is_now_locked) tuple
    """
    if not database.USE_SQLITE:
        return 0, False

    conn = database._get_db_connection()
    cursor = conn.cursor()

    # Increment failed attempts
    cursor.execute(
        "UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
        (username,)
    )

    # Check if threshold reached
    cursor.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    attempts = row["failed_attempts"] if row else 0

    is_locked = False
    if attempts >= LOCKOUT_THRESHOLD:
        # Lock the account
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        cursor.execute(
            "UPDATE users SET locked_until = ? WHERE username = ?",
            (locked_until.isoformat(), username)
        )
        is_locked = True

    conn.commit()
    conn.close()
    return attempts, is_locked


def clear_lockout(username: str):
    """Clear failed attempts and lockout for a user.

    Args:
        username: Username to clear lockout for
    """
    if not database.USE_SQLITE:
        return

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()
