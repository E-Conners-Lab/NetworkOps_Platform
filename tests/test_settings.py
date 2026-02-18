"""Tests for central configuration settings."""

import os
from unittest.mock import patch

import pytest

from config.settings import (
    AppSettings,
    AuthSettings,
    DeviceSettings,
    get_settings,
)


class TestAuthSettings:
    def test_defaults_applied(self):
        settings = AuthSettings()
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_expiration_hours == 24
        assert settings.lockout_threshold == 5
        assert settings.password_min_length == 8
        assert settings.password_require_uppercase is True

    def test_env_override(self):
        with patch.dict(os.environ, {
            "JWT_SECRET": "my-secret",
            "JWT_REFRESH_SECRET": "my-refresh",
            "JWT_EXPIRATION_HOURS": "48",
            "LOCKOUT_THRESHOLD": "10",
        }, clear=False):
            settings = AuthSettings()
            assert settings.jwt_expiration_hours == 48
            assert settings.lockout_threshold == 10

    def test_missing_jwt_secret_raises_in_production(self):
        """Missing JWT_SECRET should raise ValueError in non-test mode."""
        env = os.environ.copy()
        for key in ("JWT_SECRET", "JWT_REFRESH_SECRET", "TESTING", "FLASK_ENV"):
            env.pop(key, None)
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="JWT_SECRET"):
                AppSettings()


class TestDeviceSettings:
    def test_defaults(self):
        # Remove device env vars to test actual defaults
        env = os.environ.copy()
        env.pop("DEVICE_USERNAME", None)
        env.pop("DEVICE_PASSWORD", None)
        with patch.dict(os.environ, env, clear=True):
            settings = DeviceSettings()
            assert settings.device_username == ""
            assert settings.netconf_pool_max_per_device == 2
            assert settings.netconf_pool_max_idle_seconds == 120
            assert settings.netconf_pool_max_age_seconds == 300

    def test_env_override(self):
        with patch.dict(os.environ, {
            "DEVICE_USERNAME": "admin",
            "DEVICE_PASSWORD": "secret",
        }, clear=False):
            settings = DeviceSettings()
            assert settings.device_username == "admin"
            assert settings.device_password.get_secret_value() == "secret"


class TestSecretStr:
    def test_secret_not_in_repr(self):
        with patch.dict(os.environ, {
            "JWT_SECRET": "super-secret",
            "JWT_REFRESH_SECRET": "refresh-secret",
        }, clear=False):
            settings = AuthSettings()
            repr_str = repr(settings)
            assert "super-secret" not in repr_str
            assert "**" in repr_str

    def test_secret_value_accessible(self):
        with patch.dict(os.environ, {
            "JWT_SECRET": "my-secret",
            "JWT_REFRESH_SECRET": "my-refresh",
        }, clear=False):
            settings = AuthSettings()
            assert settings.jwt_secret.get_secret_value() == "my-secret"


class TestGetSettings:
    def test_singleton(self):
        get_settings.cache_clear()
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
        get_settings.cache_clear()

    def test_cache_clear_resets(self):
        get_settings.cache_clear()
        s1 = get_settings()
        get_settings.cache_clear()
        s2 = get_settings()
        assert s2 is not s1
        get_settings.cache_clear()

    def test_nested_groups_initialized(self):
        get_settings.cache_clear()
        s = get_settings()
        assert s.auth is not None
        assert s.redis is not None
        assert s.database is not None
        assert s.influxdb is not None
        assert s.rate_limit is not None
        assert s.devices is not None
        get_settings.cache_clear()
