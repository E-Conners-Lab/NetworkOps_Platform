"""
Tests for feature flags module.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch


class TestFeatureFlags:
    """Test feature flag functionality"""

    def test_default_flags_exist(self):
        """Verify all expected default flags are defined"""
        from core.feature_flags import flags

        flags.refresh()
        all_flags = flags.all_flags()

        expected_flags = [
            "use_aetest",
            "use_ntc_templates",
            "use_normalizer",
            "use_nornir",
            "use_batfish",
            "structured_logging",
            "metrics_enabled",
            "enable_hierarchical_view",
            "use_netbox",
            "enable_chat_history",
        ]

        for flag in expected_flags:
            assert flag in all_flags, f"Missing default flag: {flag}"

    def test_is_enabled_function(self):
        """Test the convenience is_enabled function"""
        from core.feature_flags import is_enabled

        # These should return False by default
        assert is_enabled("use_aetest") is False
        assert is_enabled("use_nornir") is False

        # These should return True by default
        assert is_enabled("use_normalizer") is True
        assert is_enabled("structured_logging") is True

    def test_unknown_flag_returns_false(self):
        """Unknown flags should return False with a warning"""
        from core.feature_flags import is_enabled

        assert is_enabled("nonexistent_flag") is False

    def test_environment_variable_override(self):
        """Environment variables should override defaults"""
        from core.feature_flags import FeatureFlags

        # Create fresh instance
        with patch.dict(os.environ, {"FF_USE_AETEST": "true"}):
            test_flags = FeatureFlags()
            test_flags.refresh()
            assert test_flags.is_enabled("use_aetest") is True

        with patch.dict(os.environ, {"FF_USE_AETEST": "false"}):
            test_flags = FeatureFlags()
            test_flags.refresh()
            assert test_flags.is_enabled("use_aetest") is False

    def test_environment_variable_formats(self):
        """Various truthy/falsy env var formats should work"""
        from core.feature_flags import FeatureFlags

        truthy_values = ["true", "True", "TRUE", "1", "yes", "on"]
        for value in truthy_values:
            with patch.dict(os.environ, {"FF_USE_AETEST": value}):
                test_flags = FeatureFlags()
                test_flags.refresh()
                assert test_flags.is_enabled("use_aetest") is True, f"Failed for value: {value}"

        falsy_values = ["false", "False", "0", "no", "off", ""]
        for value in falsy_values:
            with patch.dict(os.environ, {"FF_USE_AETEST": value}):
                test_flags = FeatureFlags()
                test_flags.refresh()
                assert test_flags.is_enabled("use_aetest") is False, f"Failed for value: {value}"

    def test_legacy_env_var_support(self):
        """Legacy environment variables should still work"""
        from core.feature_flags import FeatureFlags

        with patch.dict(os.environ, {"ENABLE_HIERARCHICAL_VIEW": "true"}):
            test_flags = FeatureFlags()
            test_flags.refresh()
            assert test_flags.is_enabled("enable_hierarchical_view") is True

        with patch.dict(os.environ, {"USE_NETBOX": "true"}):
            test_flags = FeatureFlags()
            test_flags.refresh()
            assert test_flags.is_enabled("use_netbox") is True

    def test_refresh_updates_cache(self):
        """Calling refresh should update the cache"""
        from core.feature_flags import FeatureFlags

        test_flags = FeatureFlags()
        test_flags.refresh()

        initial_value = test_flags.is_enabled("use_aetest")
        assert initial_value is False

        # Simulate env var change
        with patch.dict(os.environ, {"FF_USE_AETEST": "true"}):
            # Without refresh, should still be cached
            # (actually our impl checks _loaded, so let's verify refresh works)
            test_flags.refresh()
            assert test_flags.is_enabled("use_aetest") is True

    def test_all_flags_returns_copy(self):
        """all_flags should return a copy, not the internal cache"""
        from core.feature_flags import flags

        all_flags = flags.all_flags()
        all_flags["use_aetest"] = True  # Modify the returned dict

        # Original should be unchanged
        assert flags.is_enabled("use_aetest") is False

    def test_get_flag_info(self):
        """get_flag_info should return detailed flag information"""
        from core.feature_flags import FeatureFlags

        with patch.dict(os.environ, {"FF_USE_AETEST": "true"}):
            test_flags = FeatureFlags()
            test_flags.refresh()
            info = test_flags.get_flag_info()

            assert "use_aetest" in info
            assert info["use_aetest"]["enabled"] is True
            assert info["use_aetest"]["source"] == "environment"
            assert info["use_aetest"]["default"] is False

    def test_config_file_loading(self, tmp_path):
        """Config file should be loaded when present"""
        from core.feature_flags import FeatureFlags

        # Create temp config file
        config_file = tmp_path / "feature_flags.yaml"
        config_file.write_text("""
feature_flags:
  use_aetest: true
  use_ntc_templates: true
""")

        test_flags = FeatureFlags()
        test_flags._config_path = config_file
        test_flags.refresh()

        assert test_flags.is_enabled("use_aetest") is True
        assert test_flags.is_enabled("use_ntc_templates") is True
        # Default should still work for unspecified flags
        assert test_flags.is_enabled("use_normalizer") is True

    def test_env_var_overrides_config_file(self, tmp_path):
        """Environment variables should override config file"""
        from core.feature_flags import FeatureFlags

        # Create temp config file with use_aetest: true
        config_file = tmp_path / "feature_flags.yaml"
        config_file.write_text("""
feature_flags:
  use_aetest: true
""")

        # But env var says false
        with patch.dict(os.environ, {"FF_USE_AETEST": "false"}):
            test_flags = FeatureFlags()
            test_flags._config_path = config_file
            test_flags.refresh()

            # Env var should win
            assert test_flags.is_enabled("use_aetest") is False


class TestFeatureFlagsIntegration:
    """Integration tests for feature flags with actual config"""

    def test_actual_config_file_loads(self):
        """The actual config/feature_flags.yaml should load without error"""
        from core.feature_flags import flags

        flags.refresh()
        all_flags = flags.all_flags()

        # Should have loaded something
        assert len(all_flags) > 0

        # Check the info shows sources
        info = flags.get_flag_info()
        assert len(info) > 0
