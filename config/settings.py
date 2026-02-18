"""
Central configuration using Pydantic BaseSettings.

Validates all env vars at startup (fail-fast). Required secrets refuse
to start in production but get safe defaults in TESTING mode.

Usage:
    from config.settings import get_settings

    settings = get_settings()
    print(settings.auth.jwt_secret.get_secret_value())

Lazy initialization: get_settings() creates the singleton on first call.
Tests can reset via get_settings.cache_clear().
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings


def _is_testing() -> bool:
    """Check if running in test mode."""
    return (
        os.getenv("TESTING", "").lower() in ("true", "1")
        or os.getenv("FLASK_ENV", "") == "testing"
    )


# =============================================================================
# Nested Settings Groups
# =============================================================================


class AuthSettings(BaseSettings):
    """JWT and authentication configuration."""

    model_config = {"env_prefix": "", "extra": "ignore"}

    jwt_secret: SecretStr = SecretStr(os.getenv("JWT_SECRET", ""))
    jwt_refresh_secret: SecretStr = SecretStr(os.getenv("JWT_REFRESH_SECRET", ""))
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    jwt_refresh_expiration_days: int = 7

    # Account lockout
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 15

    # Password policy
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True

    # Sessions
    single_session_enabled: bool = True
    session_max_age_hours: int = 168  # 7 days

    # Redis token blacklist
    use_redis_blacklist: bool = False
    redis_blacklist_fail_closed: bool = False

    # Password change enforcement
    enforce_password_change: bool = True

    # MFA token expiration
    mfa_token_expiration_minutes: int = 5


class RedisSettings(BaseSettings):
    """Redis connection configuration."""

    model_config = {"env_prefix": "", "extra": "ignore"}

    redis_url: str = "redis://localhost:6379/0"
    telemetry_ttl: int = 300  # 5 minutes


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    model_config = {"env_prefix": "", "extra": "ignore"}

    database_url: Optional[str] = None  # PostgreSQL URL (optional)
    auth_db_url: Optional[str] = None  # Auth-specific DB URL (optional)

    @property
    def auth_db_path(self) -> Path:
        """Default SQLite path for auth database."""
        data_dir = Path(__file__).parent.parent / "data"
        data_dir.mkdir(exist_ok=True)
        return data_dir / "users.db"


class InfluxDBSettings(BaseSettings):
    """InfluxDB MDT storage configuration."""

    model_config = {"env_prefix": "INFLUXDB_", "extra": "ignore"}

    url: str = "http://localhost:8086"
    database: str = "networkops"
    enabled: bool = False


class RateLimitSettings(BaseSettings):
    """Rate limiting configuration."""

    model_config = {"env_prefix": "RATE_LIMIT_", "extra": "ignore"}

    default: str = "500 per minute"
    auth: str = "10 per minute"
    commands: str = "60 per minute"
    readonly: str = "1000 per minute"
    storage: Optional[str] = None  # Falls back to Redis URL


class DeviceSettings(BaseSettings):
    """Device credential and connectivity configuration."""

    model_config = {"env_prefix": "", "extra": "ignore"}

    device_username: str = ""
    device_password: SecretStr = SecretStr("")

    containerlab_vm: str = "containerlab"

    # NetBox
    use_netbox: bool = False
    netbox_refresh_interval: int = 15

    # NETCONF pool
    netconf_pool_max_per_device: int = 2
    netconf_pool_max_idle_seconds: int = 120
    netconf_pool_max_age_seconds: int = 300

    # Credential cache
    credential_cache_ttl: int = 300


# =============================================================================
# Root Settings
# =============================================================================


class AppSettings(BaseSettings):
    """Root application settings composing all sub-settings."""

    model_config = {"env_prefix": "", "extra": "ignore", "env_file": ".env", "env_file_encoding": "utf-8"}

    # Feature flags
    enable_hierarchical_view: bool = False
    mdt_external: bool = False

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = ""

    # Server
    dashboard_origin: str = "http://localhost:3000"
    socketio_async_mode: str = "threading"
    shutdown_timeout: int = 30

    # Nested groups (initialized separately to support env_prefix)
    auth: AuthSettings = None  # type: ignore[assignment]
    redis: RedisSettings = None  # type: ignore[assignment]
    database: DatabaseSettings = None  # type: ignore[assignment]
    influxdb: InfluxDBSettings = None  # type: ignore[assignment]
    rate_limit: RateLimitSettings = None  # type: ignore[assignment]
    devices: DeviceSettings = None  # type: ignore[assignment]

    @model_validator(mode="before")
    @classmethod
    def _init_nested(cls, values):
        """Initialize nested settings from environment."""
        if values.get("auth") is None:
            values["auth"] = AuthSettings()
        if values.get("redis") is None:
            values["redis"] = RedisSettings()
        if values.get("database") is None:
            values["database"] = DatabaseSettings()
        if values.get("influxdb") is None:
            values["influxdb"] = InfluxDBSettings()
        if values.get("rate_limit") is None:
            values["rate_limit"] = RateLimitSettings()
        if values.get("devices") is None:
            values["devices"] = DeviceSettings()
        return values

    @model_validator(mode="after")
    def _validate_required_secrets(self):
        """Require JWT_SECRET in production; bypass only in TESTING mode."""
        if _is_testing():
            return self

        if not os.getenv("JWT_SECRET"):
            raise ValueError(
                "JWT_SECRET env var is required. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        return self


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Get the application settings singleton.

    Lazy-initialized on first call. Validates all env vars (fail-fast).
    Tests can reset via: get_settings.cache_clear()
    """
    return AppSettings()
