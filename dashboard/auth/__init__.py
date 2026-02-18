"""
Dashboard authentication module.

Public API:
- Decorators: jwt_required, permission_required, admin_required, role_required
- Auth: authenticate_user, create_token, decode_token
- User management: get_user, create_user, update_user, delete_user
- Permissions: get_user_permissions, user_has_permission

Internal modules should import from submodules directly.
External callers should use this facade.

Import Rules:
- External callers: Use `from dashboard.auth import X` (this facade)
- Internal auth modules: Use `from .submodule import X` (direct imports)
- Ban: `from dashboard.auth import X` inside auth submodules (causes facade import)
"""

# =============================================================================
# Decorators (most commonly used)
# =============================================================================
from .decorators import (
    jwt_required,
    permission_required,
    admin_required,
    role_required,
    has_permission,
)

# =============================================================================
# Authentication
# =============================================================================
from .tokens import (
    create_token,
    decode_token,
    create_refresh_token,
    decode_refresh_token,
    invalidate_token,
    get_token_from_request,
    blacklist_token,
    is_token_blacklisted,
    cleanup_expired_blacklist,
    get_redis_blacklist_status,
)

from .identity import (
    authenticate_user,
    get_user,
    get_user_id_by_username,
    get_users_list,
    check_password_change_required,
    clear_password_change_required,
)

# =============================================================================
# User Management
# =============================================================================
from .identity import (
    create_user,
    update_user,
    delete_user,
    reactivate_user,
    change_password,
)

# =============================================================================
# Permissions & Groups
# =============================================================================
from .permissions import (
    get_user_permissions,
    get_user_groups,
    user_has_permission,
    get_all_permissions,
    get_all_groups,
    get_group,
    create_group,
    update_group,
    delete_group,
    assign_user_to_groups,
)

# =============================================================================
# Password Utilities
# =============================================================================
from .passwords import (
    hash_password,
    verify_password,
    validate_password_strength,
    is_account_locked,
    record_failed_attempt,
    clear_lockout,
)

# =============================================================================
# MFA
# =============================================================================
from .mfa import (
    create_mfa_token,
    verify_mfa_token,
    complete_mfa_login,
)

# =============================================================================
# Configuration (for external config needs)
# =============================================================================
from .config import (
    JWT_EXPIRATION_HOURS,
    JWT_REFRESH_EXPIRATION_DAYS,
    LOCKOUT_THRESHOLD,
    LOCKOUT_DURATION_MINUTES,
    PASSWORD_MIN_LENGTH,
    DEFAULT_PERMISSIONS,
    DEFAULT_GROUPS,
    DB_PATH,
)

# =============================================================================
# Database State (for checking mode)
# =============================================================================
from .database import USE_SQLITE, ENV_USERS, _token_blacklist

# =============================================================================
# Schema Initialization (for api_server.py)
# =============================================================================
from .schema import initialize as init_database

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Decorators
    "jwt_required",
    "permission_required",
    "admin_required",
    "role_required",
    "has_permission",

    # Auth
    "authenticate_user",
    "create_token",
    "decode_token",
    "create_refresh_token",
    "decode_refresh_token",
    "invalidate_token",
    "get_token_from_request",
    "blacklist_token",
    "is_token_blacklisted",
    "cleanup_expired_blacklist",
    "get_redis_blacklist_status",
    "get_user",
    "get_user_id_by_username",
    "get_users_list",
    "check_password_change_required",
    "clear_password_change_required",

    # User CRUD
    "create_user",
    "update_user",
    "delete_user",
    "reactivate_user",
    "change_password",

    # Permissions & Groups
    "get_user_permissions",
    "get_user_groups",
    "user_has_permission",
    "get_all_permissions",
    "get_all_groups",
    "get_group",
    "create_group",
    "update_group",
    "delete_group",
    "assign_user_to_groups",

    # Passwords
    "hash_password",
    "verify_password",
    "validate_password_strength",
    "is_account_locked",
    "record_failed_attempt",
    "clear_lockout",

    # MFA
    "create_mfa_token",
    "verify_mfa_token",
    "complete_mfa_login",

    # Config
    "JWT_EXPIRATION_HOURS",
    "JWT_REFRESH_EXPIRATION_DAYS",
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_DURATION_MINUTES",
    "PASSWORD_MIN_LENGTH",
    "DEFAULT_PERMISSIONS",
    "DEFAULT_GROUPS",
    "DB_PATH",

    # State
    "USE_SQLITE",
    "ENV_USERS",
    "_token_blacklist",

    # Init
    "init_database",
]
