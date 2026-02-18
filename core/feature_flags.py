"""
Dynamic Feature Flags for NetworkOps

Supports multiple configuration sources with priority:
1. Environment variables (highest priority) - FF_<FLAG_NAME>=true
2. Config file (config/feature_flags.yaml)
3. Defaults (lowest priority)

Usage:
    from core.feature_flags import is_enabled, flags

    if is_enabled("use_aetest"):
        # Use aetest framework
        ...

    # Get all flags for debugging
    print(flags.all_flags())

    # Force refresh (after config file change)
    flags.refresh()
"""

import os
from typing import Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Try to import yaml, fall back gracefully
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.warning("PyYAML not installed, config file loading disabled")


@dataclass
class FeatureFlags:
    """
    Dynamic feature flags with multiple sources.

    Priority order:
    1. Environment variables (FF_<FLAG_NAME>=true/false)
    2. Config file (config/feature_flags.yaml)
    3. Default values

    Thread-safe for reads, refresh() should be called sparingly.
    """

    _defaults: Dict[str, bool] = field(default_factory=lambda: {
        # Phase 1: pyATS Deep
        "use_aetest": False,

        # Phase 2: Multi-vendor parsing
        "use_ntc_templates": False,
        "use_normalizer": True,

        # Phase 3: Advanced tools (pick one)
        "use_nornir": False,
        "use_batfish": False,

        # Phase 4: Automation frameworks
        "use_ansible": False,

        # Observability
        "structured_logging": True,
        "metrics_enabled": True,

        # Existing features (for safe rollout control)
        "enable_hierarchical_view": False,
        "use_netbox": False,
        "enable_chat_history": True,

        # Automated device provisioning
        "automated_provisioning": False,
        "eve_ng_enabled": False,
        "containerlab_enabled": False,

        # Pre-change impact analysis
        "impact_analysis_enabled": False,
    })

    _config_path: Optional[Path] = None
    _cache: Dict[str, bool] = field(default_factory=dict)
    _loaded: bool = False

    def __post_init__(self):
        """Initialize config path relative to project root"""
        if self._config_path is None:
            # Find project root (where CLAUDE.md lives)
            current = Path(__file__).parent
            while current != current.parent:
                if (current / "CLAUDE.md").exists():
                    self._config_path = current / "config" / "feature_flags.yaml"
                    break
                current = current.parent
            else:
                # Fallback
                self._config_path = Path(__file__).parent.parent / "config" / "feature_flags.yaml"

    def _load_config_file(self) -> Dict[str, bool]:
        """Load flags from YAML config file"""
        if not YAML_AVAILABLE:
            return {}

        if self._config_path is None or not self._config_path.exists():
            return {}

        try:
            with open(self._config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("feature_flags", {})
        except Exception as e:
            logger.warning(f"Failed to load feature flags config: {e}")
            return {}

    def _load_raw_config(self) -> Dict:
        """Load raw config including nested structures."""
        if not YAML_AVAILABLE:
            return {}

        if self._config_path is None or not self._config_path.exists():
            return {}

        try:
            with open(self._config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("feature_flags", {})
        except Exception as e:
            logger.warning(f"Failed to load feature flags config: {e}")
            return {}

    def _refresh_cache(self):
        """Rebuild cache from all sources"""
        file_flags = self._load_config_file()

        for flag_name, default_value in self._defaults.items():
            # Priority: env var > config file > default
            env_key = f"FF_{flag_name.upper()}"

            if env_key in os.environ:
                # Environment variable (highest priority)
                env_value = os.environ[env_key].lower()
                self._cache[flag_name] = env_value in ('true', '1', 'yes', 'on')
            elif flag_name in file_flags:
                # Config file
                self._cache[flag_name] = bool(file_flags[flag_name])
            else:
                # Default
                self._cache[flag_name] = default_value

        # Also check for legacy env vars (backwards compatibility)
        legacy_mappings = {
            "ENABLE_HIERARCHICAL_VIEW": "enable_hierarchical_view",
            "USE_NETBOX": "use_netbox",
        }
        for legacy_env, flag_name in legacy_mappings.items():
            if legacy_env in os.environ:
                env_value = os.environ[legacy_env].lower()
                self._cache[flag_name] = env_value in ('true', '1', 'yes', 'on')

        # Handle nested configs (impact_analysis)
        raw_config = self._load_raw_config()
        if "impact_analysis" in raw_config and isinstance(raw_config["impact_analysis"], dict):
            impact_cfg = raw_config["impact_analysis"]
            if "FF_IMPACT_ANALYSIS_ENABLED" in os.environ:
                env_value = os.environ["FF_IMPACT_ANALYSIS_ENABLED"].lower()
                self._cache["impact_analysis_enabled"] = env_value in ('true', '1', 'yes', 'on')
            else:
                self._cache["impact_analysis_enabled"] = impact_cfg.get("enabled", False)

        self._loaded = True
        logger.debug(f"Feature flags loaded: {self._cache}")

    def is_enabled(self, flag_name: str) -> bool:
        """
        Check if a feature flag is enabled.

        Args:
            flag_name: Name of the flag (e.g., "use_aetest")

        Returns:
            True if enabled, False otherwise
        """
        if not self._loaded:
            self._refresh_cache()

        if flag_name not in self._cache:
            logger.warning(f"Unknown feature flag: {flag_name}")
            return False

        return self._cache.get(flag_name, False)

    def refresh(self):
        """
        Force refresh of all flags.

        Call this after modifying the config file at runtime,
        or to pick up environment variable changes.
        """
        self._loaded = False
        self._refresh_cache()

    def all_flags(self) -> Dict[str, bool]:
        """
        Get all flag values.

        Useful for debugging, dashboard display, or API endpoints.

        Returns:
            Dict of flag_name -> enabled status
        """
        if not self._loaded:
            self._refresh_cache()
        return dict(self._cache)

    def get_impact_analysis_config(self) -> Dict:
        """
        Get the full impact analysis configuration.

        Returns:
            Dict with impact analysis settings:
                - enabled: bool
                - supported_platforms: list[str]
                - analysis_timeout_sec: int
                - data_max_age_sec: int
                - rate_limit_per_user_per_minute: int
                - rate_limit_per_device_per_minute: int
        """
        # Default config
        default_config = {
            "enabled": False,
            "supported_platforms": ["cisco_xe"],
            "analysis_timeout_sec": 10,
            "data_max_age_sec": 300,
            "rate_limit_per_user_per_minute": 10,
            "rate_limit_per_device_per_minute": 2,
        }

        raw_config = self._load_raw_config()
        if "impact_analysis" in raw_config and isinstance(raw_config["impact_analysis"], dict):
            config = raw_config["impact_analysis"]
            # Merge with defaults
            result = {**default_config, **config}
        else:
            result = default_config

        # Allow env var override for enabled
        if "FF_IMPACT_ANALYSIS_ENABLED" in os.environ:
            env_value = os.environ["FF_IMPACT_ANALYSIS_ENABLED"].lower()
            result["enabled"] = env_value in ('true', '1', 'yes', 'on')

        return result

    def get_flag_info(self) -> Dict[str, Dict]:
        """
        Get detailed info about each flag including source.

        Returns:
            Dict with flag details including value and source
        """
        if not self._loaded:
            self._refresh_cache()

        file_flags = self._load_config_file()
        result = {}

        for flag_name, value in self._cache.items():
            env_key = f"FF_{flag_name.upper()}"

            if env_key in os.environ:
                source = "environment"
            elif flag_name in file_flags:
                source = "config_file"
            else:
                source = "default"

            result[flag_name] = {
                "enabled": value,
                "source": source,
                "default": self._defaults.get(flag_name, False),
            }

        return result


# Singleton instance
flags = FeatureFlags()


def is_enabled(flag_name: str) -> bool:
    """
    Convenience function to check if a feature flag is enabled.

    Args:
        flag_name: Name of the flag (e.g., "use_aetest")

    Returns:
        True if enabled, False otherwise

    Example:
        if is_enabled("use_ntc_templates"):
            from ntc_templates.parse import parse_output
            ...
    """
    return flags.is_enabled(flag_name)


def get_all_flags() -> Dict[str, bool]:
    """Get all feature flag values"""
    return flags.all_flags()


def refresh_flags():
    """Force refresh all feature flags from sources"""
    flags.refresh()


def get_impact_analysis_config() -> Dict:
    """Get the full impact analysis configuration."""
    return flags.get_impact_analysis_config()
