"""
JWT token creation, validation, and blacklisting.

Handles:
- Access token creation and decoding
- Refresh token creation and decoding
- Token blacklisting (Redis with SQLite fallback)
"""
import os
import uuid
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from flask import request

from .config import (
    JWT_SECRET,
    JWT_REFRESH_SECRET,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    JWT_REFRESH_EXPIRATION_DAYS,
    USE_REDIS_BLACKLIST,
    REDIS_BLACKLIST_FAIL_CLOSED,
    REDIS_URL,
)
from . import database

logger = logging.getLogger(__name__)

# =============================================================================
# Redis Client (lazy initialization)
# =============================================================================

_redis_client = None


def _get_redis_client():
    """Get or create Redis client for token blacklisting."""
    global _redis_client
    if _redis_client is None and USE_REDIS_BLACKLIST:
        try:
            import redis
            _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            _redis_client.ping()  # Test connection
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            _redis_client = None
    return _redis_client


# =============================================================================
# Token Creation
# =============================================================================

def create_token(username: str, role: str, user_id: int = None, permissions: list = None) -> str:
    """Create a JWT access token for authenticated user with permissions.

    Args:
        username: User's username
        role: User's role (admin, operator)
        user_id: User's database ID (optional)
        permissions: List of permission names (optional, fetched from DB if not provided)

    Returns:
        Encoded JWT access token
    """
    # Import here to avoid circular dependency
    from .permissions import get_user_permissions
    from .config import DEFAULT_PERMISSIONS

    # Get permissions from database if not provided
    if permissions is None and user_id and database.USE_SQLITE:
        permissions = get_user_permissions(user_id)
    elif permissions is None:
        # Fallback for env-based users
        permissions = ["view_topology", "run_show_commands"]
        if role == "admin":
            permissions = [p[0] for p in DEFAULT_PERMISSIONS]

    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "user_id": user_id,
        "role": role,
        "permissions": permissions,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(username: str, user_id: int = None) -> str:
    """Create a JWT refresh token (longer-lived, for getting new access tokens).

    Args:
        username: User's username
        user_id: User's database ID (optional)

    Returns:
        Encoded JWT refresh token
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "user_id": user_id,
        "jti": str(uuid.uuid4()),
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, JWT_REFRESH_SECRET, algorithm=JWT_ALGORITHM)


# =============================================================================
# Token Decoding/Validation
# =============================================================================

def decode_token(token: str) -> dict | None:
    """Decode and validate JWT access token.

    Args:
        token: Encoded JWT access token

    Returns:
        Token payload dict or None if invalid/expired/blacklisted
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Verify it's an access token (reject mfa_pending, refresh, etc.)
        if payload.get("type") != "access":
            return None

        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and is_token_blacklisted(jti):
            return None

        # Check if session is still active (single session enforcement)
        from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
        if SINGLE_SESSION_ENABLED and jti:
            if not get_session_manager().validate_session(jti):
                return None

        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def decode_refresh_token(token: str) -> dict | None:
    """Decode and validate JWT refresh token.

    Args:
        token: Encoded JWT refresh token

    Returns:
        Token payload dict or None if invalid/expired/blacklisted
    """
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET, algorithms=[JWT_ALGORITHM])

        # Verify it's a refresh token
        if payload.get("type") != "refresh":
            return None

        # Check if token is blacklisted
        jti = payload.get("jti")
        if jti and is_token_blacklisted(jti):
            return None

        # Check if session is still active (single session enforcement)
        from dashboard.sessions import get_session_manager, SINGLE_SESSION_ENABLED
        if SINGLE_SESSION_ENABLED and jti:
            if not get_session_manager().validate_session(jti):
                return None

        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def invalidate_token(token: str, is_refresh: bool = False) -> bool:
    """Invalidate a token by adding it to the blacklist.

    Args:
        token: JWT token to invalidate
        is_refresh: True if this is a refresh token

    Returns:
        True if successfully blacklisted, False otherwise
    """
    try:
        if is_refresh:
            payload = jwt.decode(token, JWT_REFRESH_SECRET, algorithms=[JWT_ALGORITHM],
                                 options={"verify_exp": False})
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                                 options={"verify_exp": False})

        jti = payload.get("jti")
        exp = payload.get("exp")

        if jti and exp:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            blacklist_token(jti, expires_at)
            return True
    except Exception:
        pass
    return False


def get_token_from_request() -> str | None:
    """Extract JWT token from Authorization header.

    Returns:
        Token string or None if not present
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


# =============================================================================
# Token Blacklisting
# =============================================================================

def blacklist_token(jti: str, expires_at: datetime, token_type: str = "access"):
    """Add a token to the blacklist with appropriate TTL.

    Uses Redis if available (with TTL for auto-expiry), falls back to SQLite/in-memory.
    OWASP A07:2021 - Proper session invalidation.

    Args:
        jti: Token's unique identifier
        expires_at: When the token expires
        token_type: "access" or "refresh"
    """
    # Calculate TTL in seconds for Redis
    if token_type == "refresh":
        expires_in = int(os.getenv("JWT_REFRESH_EXPIRATION_DAYS", "7")) * 86400
    else:
        expires_in = int(os.getenv("JWT_EXPIRATION_HOURS", "24")) * 3600

    # Try Redis first if enabled
    if USE_REDIS_BLACKLIST:
        client = _get_redis_client()
        if client:
            try:
                client.setex(f"blacklist:{jti}", expires_in, "1")
                return  # Success - no need for SQLite fallback
            except Exception as e:
                logger.warning(f"Redis blacklist write failed: {e}")
                if REDIS_BLACKLIST_FAIL_CLOSED:
                    raise RuntimeError(f"Redis blacklist unavailable (fail-closed mode): {e}")
                # Fall through to SQLite/in-memory fallback

    # SQLite/in-memory fallback
    if not database.USE_SQLITE:
        database._token_blacklist.add(jti)
        return

    conn = database._get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO token_blacklist (jti, expires_at) VALUES (?, ?)",
            (jti, expires_at.isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already blacklisted
    conn.close()


def is_token_blacklisted(jti: str) -> bool:
    """Check if a token is blacklisted.

    Checks Redis first if available, falls back to SQLite/in-memory.
    OWASP A07:2021 - Proper session validation.

    Args:
        jti: Token's unique identifier

    Returns:
        True if blacklisted, False otherwise
    """
    # Try Redis first if enabled
    if USE_REDIS_BLACKLIST:
        client = _get_redis_client()
        if client:
            try:
                return client.exists(f"blacklist:{jti}") > 0
            except Exception as e:
                logger.warning(f"Redis blacklist read failed: {e}")
                if REDIS_BLACKLIST_FAIL_CLOSED:
                    return True  # Fail-closed: assume blacklisted if can't verify
                # Fall through to SQLite/in-memory fallback

    # SQLite/in-memory fallback
    if not database.USE_SQLITE:
        return jti in database._token_blacklist

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM token_blacklist WHERE jti = ?", (jti,))
    result = cursor.fetchone() is not None
    conn.close()
    return result


def cleanup_expired_blacklist():
    """Remove expired tokens from blacklist (call periodically).

    Redis handles this automatically with TTL. This is for SQLite only.
    """
    if not database.USE_SQLITE:
        return

    conn = database._get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM token_blacklist WHERE expires_at < ?",
        (datetime.now(timezone.utc).isoformat(),)
    )
    conn.commit()
    conn.close()


def get_redis_blacklist_status() -> dict:
    """Return Redis blacklist health status for monitoring.

    Returns:
        Dict with availability status and backend info
    """
    client = _get_redis_client()
    if client:
        try:
            info = client.info("server")
            return {
                "available": True,
                "backend": "redis",
                "redis_version": info.get("redis_version"),
                "connected_clients": client.info("clients").get("connected_clients")
            }
        except Exception:
            pass
    return {
        "available": False,
        "backend": "in-memory",
        "warning": "Token blacklist not distributed across workers"
    }
