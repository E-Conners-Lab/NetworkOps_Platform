"""
User identity management: authentication and CRUD operations.

Handles:
- User authentication (password verification, MFA flow)
- User CRUD (create, read, update, delete, reactivate)
- User listing and lookup
"""
import logging
import sqlite3

import jwt

from werkzeug.security import generate_password_hash

from .config import (
    DEFAULT_PERMISSIONS,
    LOCKOUT_THRESHOLD,
    LOCKOUT_DURATION_MINUTES,
)
from . import database
from .passwords import (
    verify_password,
    validate_password_strength,
    is_account_locked,
    record_failed_attempt,
    clear_lockout,
)
from .tokens import create_token, create_refresh_token

logger = logging.getLogger(__name__)


# =============================================================================
# User Lookup Functions
# =============================================================================

def _get_user_from_db(username: str) -> dict | None:
    """Get user from SQLite database."""
    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    return None


def get_user(username: str) -> dict | None:
    """Get user from database or env fallback.

    Args:
        username: Username to look up

    Returns:
        User dict or None if not found
    """
    if database.USE_SQLITE:
        return _get_user_from_db(username)
    else:
        user = database.ENV_USERS.get(username)
        if user:
            return {"username": username, **user}
        return None


def get_user_id_by_username(username: str) -> int | None:
    """Get user ID by username.

    Args:
        username: Username to look up

    Returns:
        User ID or None if not found
    """
    if not database.USE_SQLITE:
        return None

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    return row["id"] if row else None


def get_users_list() -> list[dict]:
    """Get list of all users with their groups.

    Returns:
        List of user dicts with groups
    """
    if not database.USE_SQLITE:
        return [
            {"username": username, "role": user["role"], "groups": []}
            for username, user in database.ENV_USERS.items()
        ]

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, is_active, created_at, updated_at FROM users ORDER BY username"
    )

    users = []
    for row in cursor.fetchall():
        user = {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "groups": [],
        }

        # Get user's groups
        cursor.execute("""
            SELECT g.id, g.name FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = ?
        """, (row["id"],))
        user["groups"] = [{"id": r["id"], "name": r["name"]} for r in cursor.fetchall()]

        users.append(user)

    conn.close()
    return users


# =============================================================================
# Password Change Requirement
# =============================================================================

def check_password_change_required(username: str) -> bool:
    """Check if user must change password before proceeding.

    OWASP A07:2021 - Force password change for default credentials.

    Args:
        username: Username to check

    Returns:
        True if password change required
    """
    if not database.USE_SQLITE:
        return False  # In-memory mode doesn't track this

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_change_required FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return bool(row and row[0])


def clear_password_change_required(username: str) -> None:
    """Clear the password change flag after successful change.

    Called after user successfully changes their password.

    Args:
        username: Username to clear flag for
    """
    if not database.USE_SQLITE:
        return

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_change_required = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    logger.info(f"Password change requirement cleared for user: {username}")


# =============================================================================
# Authentication
# =============================================================================

def authenticate_user(username: str, password: str) -> tuple[bool, dict | None, str | None]:
    """Authenticate user with username and password.

    Returns:
        (success, auth_data, error_message) tuple
        auth_data includes: token, refresh_token, permissions, groups
        Or if MFA required: mfa_required=True, mfa_token

    If MFA is enabled for the user, returns mfa_required=True with mfa_token instead
    of actual tokens. Client must then call /api/auth/mfa/verify with TOTP code.
    """
    # Import here to avoid circular dependencies
    from .permissions import get_user_permissions, get_user_groups
    from .mfa import create_mfa_token

    # Check if account is locked
    is_locked, remaining = is_account_locked(username)
    if is_locked:
        return False, None, f"Account locked. Try again in {remaining} seconds"

    user = get_user(username)
    if not user:
        # Don't reveal if user exists - still check lockout for timing attack prevention
        return False, None, "Invalid username or password"

    if not verify_password(password, user["password_hash"]):
        # Record failed attempt
        attempts, now_locked = record_failed_attempt(username)
        if now_locked:
            return False, None, f"Account locked after {LOCKOUT_THRESHOLD} failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes"
        remaining_attempts = LOCKOUT_THRESHOLD - attempts
        return False, None, f"Invalid username or password ({remaining_attempts} attempts remaining)"

    # Successful login - clear any failed attempts
    clear_lockout(username)

    user_id = user.get("id")
    permissions = get_user_permissions(user_id) if user_id and database.USE_SQLITE else []
    groups = get_user_groups(user_id) if user_id and database.USE_SQLITE else []

    # Fallback permissions for env-based users
    if not permissions:
        permissions = ["view_topology", "run_show_commands"]
        if user["role"] == "admin":
            permissions = [p[0] for p in DEFAULT_PERMISSIONS]

    # Check if MFA is required for this user
    from dashboard.mfa import get_mfa_manager, MFA_ENABLED
    if MFA_ENABLED and user_id:
        if get_mfa_manager().is_mfa_required(user_id):
            # Return MFA token instead of actual tokens
            mfa_token = create_mfa_token(username, user_id, user["role"], permissions)
            return True, {
                "mfa_required": True,
                "mfa_token": mfa_token,
                "message": "MFA verification required"
            }, None

    # No MFA required - create actual tokens
    token = create_token(username, user["role"], user_id, permissions)
    refresh_token = create_refresh_token(username, user_id)

    # Extract JTIs for session tracking
    access_jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    refresh_jti = jwt.decode(refresh_token, options={"verify_signature": False})["jti"]

    # Create session (invalidates all previous sessions for this user)
    from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
    session_id = None
    if SINGLE_SESSION_ENABLED and user_id:
        session_id = get_session_manager().create_session(user_id, access_jti, refresh_jti)

    auth_data = {
        "token": token,
        "refresh_token": refresh_token,
        "permissions": permissions,
        "groups": [g["name"] for g in groups],
    }

    if session_id:
        auth_data["session_id"] = session_id

    return True, auth_data, None


# =============================================================================
# User CRUD Operations
# =============================================================================

def create_user(username: str, password: str, role: str = "operator", skip_password_validation: bool = False) -> tuple[bool, str]:
    """Create a new user.

    Args:
        username: Unique username
        password: Plain text password
        role: "admin" or "operator"
        skip_password_validation: Set to True to bypass complexity check (for dev/testing only)

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "User creation requires SQLite (env-based users are read-only)"

    if not username or not password:
        return False, "Username and password are required"

    if role not in ("admin", "operator"):
        return False, "Role must be 'admin' or 'operator'"

    # Validate password strength (unless explicitly skipped for dev)
    if not skip_password_validation:
        is_valid, error = validate_password_strength(password)
        if not is_valid:
            return False, error

    try:
        conn = database._get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
        return True, f"User '{username}' created successfully"
    except sqlite3.IntegrityError:
        return False, f"User '{username}' already exists"
    except Exception as e:
        return False, f"Failed to create user: {e}"


def update_user(username: str, password: str = None, role: str = None, is_active: bool = None) -> tuple[bool, str]:
    """Update an existing user.

    Args:
        username: User to update
        password: New password (optional)
        role: New role (optional)
        is_active: Active status (optional)

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "User updates require SQLite (env-based users are read-only)"

    user = _get_user_from_db(username)
    if not user:
        return False, f"User '{username}' not found"

    updates = []
    params = []

    if password is not None:
        is_valid, error = validate_password_strength(password)
        if not is_valid:
            return False, error
        updates.append("password_hash = ?")
        params.append(generate_password_hash(password))

    if role is not None:
        if role not in ("admin", "operator"):
            return False, "Role must be 'admin' or 'operator'"
        updates.append("role = ?")
        params.append(role)

    if is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if is_active else 0)

    if not updates:
        return False, "No updates provided"

    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(username)

    try:
        conn = database._get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE username = ?",  # nosec B608
            params
        )
        conn.commit()
        conn.close()
        return True, f"User '{username}' updated successfully"
    except Exception as e:
        return False, f"Failed to update user: {e}"


def delete_user(username: str, hard_delete: bool = False) -> tuple[bool, str]:
    """Delete a user (soft delete by default, hard delete if specified).

    Args:
        username: User to delete
        hard_delete: If True, permanently delete; if False, deactivate

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "User deletion requires SQLite (env-based users are read-only)"

    user = _get_user_from_db(username)
    if not user:
        return False, f"User '{username}' not found"

    # Prevent deleting the last admin
    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")
    admin_count = cursor.fetchone()[0]

    if user["role"] == "admin" and admin_count <= 1:
        conn.close()
        return False, "Cannot delete the last admin user"

    try:
        if hard_delete:
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        else:
            cursor.execute(
                "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (username,)
            )
        conn.commit()
        conn.close()
        action = "deleted" if hard_delete else "deactivated"
        return True, f"User '{username}' {action} successfully"
    except Exception as e:
        conn.close()
        return False, f"Failed to delete user: {e}"


def reactivate_user(username: str) -> tuple[bool, str]:
    """Reactivate a deactivated user.

    Args:
        username: User to reactivate

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "User reactivation requires SQLite"

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, f"User '{username}' not found"

    if row["is_active"]:
        conn.close()
        return False, f"User '{username}' is already active"

    try:
        cursor.execute(
            "UPDATE users SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
            (username,)
        )
        conn.commit()
        conn.close()
        return True, f"User '{username}' reactivated successfully"
    except Exception as e:
        conn.close()
        return False, f"Failed to reactivate user: {e}"


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Change user's password (requires old password verification).

    Args:
        username: User to change password for
        old_password: Current password for verification
        new_password: New password

    Returns:
        (success, message) tuple
    """
    if not database.USE_SQLITE:
        return False, "Password change requires SQLite"

    user = get_user(username)
    if not user:
        return False, "User not found"

    if not verify_password(old_password, user["password_hash"]):
        return False, "Current password is incorrect"

    # Validate new password strength
    is_valid, error = validate_password_strength(new_password)
    if not is_valid:
        return False, error

    return update_user(username, password=new_password)
