"""
Auth domain types - no dependencies on other auth modules.

NOTE: Keep this minimal. Only add types here if they are:
1. Used by 3+ auth submodules, AND
2. Would otherwise cause circular imports
"""
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class UserInfo:
    """User identity from database (immutable)."""
    id: int
    username: str
    role: str
    groups: tuple[str, ...]
    permissions: tuple[str, ...]
    mfa_enabled: bool = False
    password_change_required: bool = False


@dataclass(frozen=True)
class TokenPayload:
    """Decoded JWT payload (immutable)."""
    sub: str  # username
    user_id: int
    role: str
    permissions: tuple[str, ...]
    exp: datetime
    iat: datetime
    jti: str  # token ID for blacklisting
    token_type: str = "access"  # access, refresh, mfa_pending
