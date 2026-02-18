"""
Multi-factor authentication (MFA) token handling.

Handles MFA tokens for two-step authentication flow:
1. User authenticates with password → MFA token returned
2. User verifies TOTP code with MFA token → actual tokens returned

Note: The TOTP management (enrollment, verification) is in dashboard/mfa.py.
This module only handles the auth-side MFA token flow.
"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from .config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    MFA_TOKEN_EXPIRATION_MINUTES,
    DEFAULT_PERMISSIONS,
)
from . import database
from .tokens import create_token, create_refresh_token
from .permissions import get_user_permissions, get_user_groups


def create_mfa_token(username: str, user_id: int, role: str, permissions: list) -> str:
    """Create a temporary MFA token for two-step authentication.

    This token is returned after password verification when MFA is required.
    It must be exchanged for actual tokens after TOTP verification.

    Args:
        username: User's username
        user_id: User's database ID
        role: User's role
        permissions: User's permissions list

    Returns:
        JWT MFA token
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "user_id": user_id,
        "role": role,
        "permissions": permissions,
        "jti": str(uuid.uuid4()),
        "type": "mfa_pending",
        "iat": now,
        "exp": now + timedelta(minutes=MFA_TOKEN_EXPIRATION_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_mfa_token(token: str) -> dict | None:
    """Verify an MFA token and return user info.

    Args:
        token: JWT MFA token

    Returns:
        Dict with user_id, username, role, permissions or None if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Verify it's an MFA token
        if payload.get("type") != "mfa_pending":
            return None

        return {
            "user_id": payload.get("user_id"),
            "username": payload.get("sub"),
            "role": payload.get("role"),
            "permissions": payload.get("permissions", [])
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def complete_mfa_login(user_id: int, username: str) -> dict | None:
    """Complete login after MFA verification - generate actual tokens.

    Called after TOTP code has been verified. Generates access and refresh tokens.

    Args:
        user_id: User's database ID
        username: Username

    Returns:
        Dict with token, refresh_token, permissions, groups or None on failure
    """
    # Import here to avoid circular dependency
    from .identity import get_user

    user = get_user(username)
    if not user:
        return None

    permissions = get_user_permissions(user_id) if user_id and database.USE_SQLITE else []
    groups = get_user_groups(user_id) if user_id and database.USE_SQLITE else []

    # Fallback permissions for env-based users
    if not permissions:
        permissions = ["view_topology", "run_show_commands"]
        if user["role"] == "admin":
            permissions = [p[0] for p in DEFAULT_PERMISSIONS]

    # Create actual tokens
    token = create_token(username, user["role"], user_id, permissions)
    refresh_token = create_refresh_token(username, user_id)

    # Extract JTIs for session tracking
    access_jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    refresh_jti = jwt.decode(refresh_token, options={"verify_signature": False})["jti"]

    # Create session
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

    return auth_data
