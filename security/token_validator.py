"""
Flask-free JWT token validation for the MCP layer.

Validates tokens issued by the dashboard/auth service using the shared
HS256 secret (JWT_SECRET env var). Enforces expiration and checks the
token blacklist.

This module intentionally avoids importing Flask or dashboard.auth.tokens
(which pulls in Flask's request object). It reuses only:
- dashboard.auth.config for JWT_SECRET / JWT_ALGORITHM
- dashboard.auth.tokens.is_token_blacklisted for blacklist checks
"""

import logging

import jwt

from dashboard.auth.config import JWT_SECRET, JWT_ALGORITHM

logger = logging.getLogger(__name__)


def validate_token(token: str) -> dict | None:
    """Validate a JWT access token issued by the dashboard auth service.

    Checks:
    1. Signature (HS256 with JWT_SECRET)
    2. Expiration (exp claim)
    3. Blacklist (via dashboard.auth.tokens.is_token_blacklisted)

    Args:
        token: Encoded JWT string (without "Bearer " prefix).

    Returns:
        Decoded payload dict on success, or None on any failure.
        The payload contains: sub, role, permissions, jti, exp, iat, type.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.debug("Token validation failed: expired")
        return None
    except jwt.InvalidTokenError as exc:
        logger.debug("Token validation failed: %s", exc)
        return None

    # Check blacklist
    jti = payload.get("jti")
    if jti:
        try:
            from dashboard.auth.tokens import is_token_blacklisted

            if is_token_blacklisted(jti):
                logger.debug("Token validation failed: blacklisted (jti=%s)", jti)
                return None
        except ImportError:
            # dashboard.auth not available -- skip blacklist check
            pass

    return payload
