"""
Auth configuration constants - no dependencies on other auth modules.

All auth configuration is centralized here for easy auditing.
Values are sourced from config.settings (Pydantic BaseSettings).
Backwards-compatible: all existing names are preserved as module-level constants.
"""
from config.settings import get_settings

_settings = get_settings()
_auth = _settings.auth

# =============================================================================
# JWT Configuration
# =============================================================================

JWT_SECRET = _auth.jwt_secret.get_secret_value()
JWT_REFRESH_SECRET = _auth.jwt_refresh_secret.get_secret_value()
JWT_ALGORITHM = _auth.jwt_algorithm
JWT_EXPIRATION_HOURS = _auth.jwt_expiration_hours
JWT_REFRESH_EXPIRATION_DAYS = _auth.jwt_refresh_expiration_days

# MFA token expiration (short-lived for two-step auth)
MFA_TOKEN_EXPIRATION_MINUTES = _auth.mfa_token_expiration_minutes

# =============================================================================
# Account Lockout Configuration
# =============================================================================

LOCKOUT_THRESHOLD = _auth.lockout_threshold
LOCKOUT_DURATION_MINUTES = _auth.lockout_duration_minutes

# =============================================================================
# Password Policy Configuration
# =============================================================================

PASSWORD_MIN_LENGTH = _auth.password_min_length
PASSWORD_REQUIRE_UPPERCASE = _auth.password_require_uppercase
PASSWORD_REQUIRE_LOWERCASE = _auth.password_require_lowercase
PASSWORD_REQUIRE_DIGIT = _auth.password_require_digit
PASSWORD_REQUIRE_SPECIAL = _auth.password_require_special

# =============================================================================
# Database Configuration
# =============================================================================

DB_PATH = _settings.database.auth_db_path

# =============================================================================
# Redis Token Blacklist Configuration
# =============================================================================

USE_REDIS_BLACKLIST = _auth.use_redis_blacklist
REDIS_BLACKLIST_FAIL_CLOSED = _auth.redis_blacklist_fail_closed
REDIS_URL = _settings.redis.redis_url

# =============================================================================
# Default Permissions and Groups
# =============================================================================

# All available permissions in the system
DEFAULT_PERMISSIONS = [
    ("view_topology", "View network topology and device status"),
    ("run_show_commands", "Execute read-only show commands on devices"),
    ("run_config_commands", "Execute configuration commands on devices"),
    ("remediate_interfaces", "Bounce or shutdown interfaces"),
    ("manage_users", "Create, edit, and delete user accounts"),
    ("manage_groups", "Manage group permissions and memberships"),
]

# Default groups created on database initialization
DEFAULT_GROUPS = {
    "Network Admins": {
        "description": "Full access to all network operations",
        "permissions": [p[0] for p in DEFAULT_PERMISSIONS],
    },
    "NOC Operators": {
        "description": "Read-only access for monitoring",
        "permissions": ["view_topology", "run_show_commands"],
    },
    "Network Engineers": {
        "description": "Configuration access for network changes",
        "permissions": ["view_topology", "run_show_commands", "run_config_commands", "remediate_interfaces"],
    },
}
