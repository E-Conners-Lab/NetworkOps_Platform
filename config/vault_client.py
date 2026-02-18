"""
HashiCorp Vault client module.

Provides centralized secrets management with caching and .env fallback.
Supports both token auth (dev) and AppRole auth (production).
"""

import os
import time
import logging
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class VaultConfig:
    """Vault configuration loaded from environment."""

    vault_addr: str
    vault_token: str  # For dev/token auth
    vault_role_id: str  # For AppRole auth (production)
    vault_secret_id: str
    vault_mount_path: str
    vault_namespace: str
    use_vault: bool
    cache_ttl: int

    @classmethod
    def from_env(cls) -> "VaultConfig":
        """Create configuration from environment variables."""
        return cls(
            vault_addr=os.getenv("VAULT_ADDR", "http://localhost:8200"),
            vault_token=os.getenv("VAULT_TOKEN", ""),
            vault_role_id=os.getenv("VAULT_ROLE_ID", ""),
            vault_secret_id=os.getenv("VAULT_SECRET_ID", ""),
            vault_mount_path=os.getenv("VAULT_MOUNT_PATH", "secret"),
            vault_namespace=os.getenv("VAULT_NAMESPACE", ""),
            use_vault=os.getenv("USE_VAULT", "false").lower() == "true",
            cache_ttl=int(os.getenv("VAULT_CACHE_TTL", "300")),
        )


class VaultClient:
    """HashiCorp Vault client with caching and fallback."""

    def __init__(self, config: VaultConfig | None = None):
        """Initialize Vault client.

        Args:
            config: VaultConfig instance, or None to load from env
        """
        self.config = config or VaultConfig.from_env()
        self._client = None
        self._cache: dict[str, Any] = {}
        self._cache_timestamps: dict[str, float] = {}
        self._authenticated = False

    @property
    def client(self):
        """Lazy-load hvac client."""
        if self._client is None:
            try:
                import hvac

                self._client = hvac.Client(
                    url=self.config.vault_addr,
                    namespace=self.config.vault_namespace or None,
                )

                # Authenticate
                if self.config.vault_token:
                    # Token auth (development)
                    self._client.token = self.config.vault_token
                    self._authenticated = True
                elif self.config.vault_role_id and self.config.vault_secret_id:
                    # AppRole auth (production)
                    self._client.auth.approle.login(
                        role_id=self.config.vault_role_id,
                        secret_id=self.config.vault_secret_id,
                    )
                    self._authenticated = True

                # Verify authentication
                if self._authenticated and not self._client.is_authenticated():
                    logger.warning("Vault authentication failed")
                    self._authenticated = False

            except ImportError:
                logger.warning("hvac not installed, Vault integration disabled")
                self._client = None
            except Exception as e:
                logger.warning(f"Failed to connect to Vault: {e}")
                self._client = None

        return self._client

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cache entry is still valid."""
        if key not in self._cache_timestamps:
            return False
        return (time.time() - self._cache_timestamps[key]) < self.config.cache_ttl

    def _get_cached(self, key: str) -> Any | None:
        """Get value from cache if valid."""
        if self._is_cache_valid(key):
            return self._cache.get(key)
        return None

    def _set_cached(self, key: str, value: Any) -> None:
        """Set value in cache."""
        self._cache[key] = value
        self._cache_timestamps[key] = time.time()

    def refresh_cache(self) -> None:
        """Clear all cached secrets."""
        self._cache.clear()
        self._cache_timestamps.clear()

    def is_available(self) -> bool:
        """Check if Vault is available and authenticated."""
        if not self.config.use_vault:
            return False
        return self.client is not None and self._authenticated

    def get_secret(self, path: str, key: str) -> str | None:
        """Get a single secret value from Vault.

        Args:
            path: Secret path (e.g., "networkops/jwt")
            key: Key within the secret (e.g., "secret")

        Returns:
            Secret value or None
        """
        secrets = self.get_secrets(path)
        return secrets.get(key) if secrets else None

    def get_secrets(self, path: str) -> dict[str, str] | None:
        """Get all secrets at a path from Vault.

        Args:
            path: Secret path (e.g., "networkops/jwt")

        Returns:
            Dict of key-value pairs or None
        """
        cache_key = f"secrets:{path}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        if not self.is_available():
            return None

        try:
            # KV v2 read
            full_path = f"{self.config.vault_mount_path}/data/{path}"
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.config.vault_mount_path,
            )
            if response and "data" in response and "data" in response["data"]:
                secrets = response["data"]["data"]
                self._set_cached(cache_key, secrets)
                return secrets
        except Exception as e:
            logger.debug(f"Failed to read secret at {path}: {e}")

        return None


class SecretsManager:
    """High-level secrets interface with .env fallback.

    Usage:
        secrets = SecretsManager()
        jwt_secret = secrets.get_jwt_secret()
        username, password = secrets.get_device_credentials()
    """

    def __init__(self, vault_client: VaultClient | None = None):
        """Initialize secrets manager.

        Args:
            vault_client: VaultClient instance, or None to create one
        """
        self._vault = vault_client or VaultClient()

    def _get_from_vault_or_env(
        self,
        vault_path: str,
        vault_key: str,
        env_var: str,
        default: str = "",
    ) -> str:
        """Get secret from Vault, falling back to environment variable.

        Args:
            vault_path: Vault secret path
            vault_key: Key within the Vault secret
            env_var: Environment variable name for fallback
            default: Default value if neither source has the secret

        Returns:
            Secret value
        """
        # Try Vault first
        if self._vault.is_available():
            value = self._vault.get_secret(vault_path, vault_key)
            if value:
                return value

        # Fall back to environment variable
        return os.getenv(env_var, default)

    def get_jwt_secret(self) -> str:
        """Get JWT signing secret."""
        secret = self._get_from_vault_or_env(
            vault_path="networkops/jwt",
            vault_key="secret",
            env_var="JWT_SECRET",
            default="",
        )
        if not secret:
            raise ValueError(
                "JWT_SECRET env var is required. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        return secret

    def get_jwt_refresh_secret(self) -> str:
        """Get JWT refresh token secret."""
        refresh_secret = self._get_from_vault_or_env(
            vault_path="networkops/jwt",
            vault_key="refresh_secret",
            env_var="JWT_REFRESH_SECRET",
            default="",
        )
        if not refresh_secret:
            raise ValueError(
                "JWT_REFRESH_SECRET env var is required. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        return refresh_secret

    def get_device_credentials(self) -> tuple[str, str]:
        """Get device SSH credentials.

        Returns:
            Tuple of (username, password)
        """
        username = self._get_from_vault_or_env(
            vault_path="networkops/devices",
            vault_key="username",
            env_var="DEVICE_USERNAME",
            default="admin",
        )
        password = self._get_from_vault_or_env(
            vault_path="networkops/devices",
            vault_key="password",
            env_var="DEVICE_PASSWORD",
            default="admin",
        )
        if username == "admin" and password == "admin":
            logger.warning("Using default device credentials (admin/admin). Set DEVICE_USERNAME and DEVICE_PASSWORD for production.")
        return username, password

    def get_api_key(self, service: str) -> str | None:
        """Get API key for a service.

        Args:
            service: Service name (anthropic, discord, netbox)

        Returns:
            API key or None
        """
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "discord": "DISCORD_BOT_TOKEN",
            "netbox": "NETBOX_API_TOKEN",
            "mcp": "MCP_AUTH_TOKEN",
        }
        env_var = env_map.get(service)
        if not env_var:
            return None

        return self._get_from_vault_or_env(
            vault_path="networkops/api_keys",
            vault_key=service,
            env_var=env_var,
            default="",
        ) or None

    def get_mfa_encryption_key(self) -> str:
        """Get MFA TOTP encryption key."""
        return self._get_from_vault_or_env(
            vault_path="networkops/mfa",
            vault_key="encryption_key",
            env_var="MFA_ENCRYPTION_KEY",
            default="",
        )

    def get_netbox_token(self) -> str:
        """Get NetBox API token."""
        return self._get_from_vault_or_env(
            vault_path="networkops/api_keys",
            vault_key="netbox",
            env_var="NETBOX_API_TOKEN",
            default="",
        )

    def get_siem_credentials(self) -> dict[str, str]:
        """Get SIEM credentials (Splunk token, Elasticsearch password/api_key).

        Returns:
            Dict with keys: splunk_token, elasticsearch_password, elasticsearch_api_key
        """
        return {
            "splunk_token": self._get_from_vault_or_env(
                vault_path="networkops/siem",
                vault_key="splunk_token",
                env_var="SIEM_SPLUNK_TOKEN",
                default="",
            ),
            "elasticsearch_password": self._get_from_vault_or_env(
                vault_path="networkops/siem",
                vault_key="elasticsearch_password",
                env_var="SIEM_ELASTICSEARCH_PASSWORD",
                default="",
            ),
            "elasticsearch_api_key": self._get_from_vault_or_env(
                vault_path="networkops/siem",
                vault_key="elasticsearch_api_key",
                env_var="SIEM_ELASTICSEARCH_API_KEY",
                default="",
            ),
        }

    def get_eve_ng_credentials(self) -> tuple[str, str]:
        """Get EVE-NG API credentials.

        Returns:
            Tuple of (username, password)
        """
        username = self._get_from_vault_or_env(
            vault_path="networkops/eve_ng",
            vault_key="username",
            env_var="EVE_NG_USERNAME",
            default="admin",
        )
        password = self._get_from_vault_or_env(
            vault_path="networkops/eve_ng",
            vault_key="password",
            env_var="EVE_NG_PASSWORD",
            default="eve",
        )
        return username, password

    def get_snmp_v3_credentials(self) -> tuple[str, str, str]:
        """Get SNMPv3 default credentials.

        Returns:
            Tuple of (username, auth_password, priv_password)
        """
        username = self._get_from_vault_or_env(
            vault_path="networkops/snmp_v3",
            vault_key="username",
            env_var="SNMP_V3_USERNAME",
            default="",
        )
        auth_password = self._get_from_vault_or_env(
            vault_path="networkops/snmp_v3",
            vault_key="auth_password",
            env_var="SNMP_V3_AUTH_PASSWORD",
            default="",
        )
        priv_password = self._get_from_vault_or_env(
            vault_path="networkops/snmp_v3",
            vault_key="priv_password",
            env_var="SNMP_V3_PRIV_PASSWORD",
            default="",
        )
        return username, auth_password, priv_password

    def get_mcp_auth_token(self) -> str:
        """Get MCP authentication token."""
        return self._get_from_vault_or_env(
            vault_path="networkops/api_keys",
            vault_key="mcp",
            env_var="MCP_AUTH_TOKEN",
            default="",
        )

    def get_admin_password(self) -> str:
        """Get dashboard admin default password."""
        return self._get_from_vault_or_env(
            vault_path="networkops/dashboard",
            vault_key="admin_password",
            env_var="DASHBOARD_ADMIN_PASSWORD",
            default="admin",
        )

    def get_webhook_urls(self) -> dict[str, str | None]:
        """Get webhook URLs for notification targets.

        Returns:
            Dict with keys: slack_url, teams_url, discord_url, pagerduty_key, generic_url
            Values are None when not configured.
        """
        return {
            "slack_url": self._get_from_vault_or_env(
                vault_path="networkops/webhooks",
                vault_key="slack_url",
                env_var="SLACK_WEBHOOK_URL",
                default="",
            ) or None,
            "teams_url": self._get_from_vault_or_env(
                vault_path="networkops/webhooks",
                vault_key="teams_url",
                env_var="TEAMS_WEBHOOK_URL",
                default="",
            ) or None,
            "discord_url": self._get_from_vault_or_env(
                vault_path="networkops/webhooks",
                vault_key="discord_url",
                env_var="DISCORD_WEBHOOK_URL",
                default="",
            ) or None,
            "pagerduty_key": self._get_from_vault_or_env(
                vault_path="networkops/webhooks",
                vault_key="pagerduty_key",
                env_var="PAGERDUTY_ROUTING_KEY",
                default="",
            ) or None,
            "generic_url": self._get_from_vault_or_env(
                vault_path="networkops/webhooks",
                vault_key="generic_url",
                env_var="GENERIC_WEBHOOK_URL",
                default="",
            ) or None,
        }

    def is_vault_available(self) -> bool:
        """Check if Vault is available."""
        return self._vault.is_available()


# Singleton instance
_secrets_manager: SecretsManager | None = None


def get_secrets_manager() -> SecretsManager:
    """Get or create SecretsManager singleton.

    Returns:
        SecretsManager instance
    """
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Convenience functions
def get_jwt_secret() -> str:
    """Get JWT signing secret."""
    return get_secrets_manager().get_jwt_secret()


def get_jwt_refresh_secret() -> str:
    """Get JWT refresh token secret."""
    return get_secrets_manager().get_jwt_refresh_secret()


def get_device_credentials() -> tuple[str, str]:
    """Get device SSH credentials."""
    return get_secrets_manager().get_device_credentials()


def get_api_key(service: str) -> str | None:
    """Get API key for a service."""
    return get_secrets_manager().get_api_key(service)


def get_mfa_encryption_key() -> str:
    """Get MFA encryption key."""
    return get_secrets_manager().get_mfa_encryption_key()


def get_netbox_token() -> str:
    """Get NetBox API token."""
    return get_secrets_manager().get_netbox_token()


def get_siem_credentials() -> dict[str, str]:
    """Get SIEM credentials."""
    return get_secrets_manager().get_siem_credentials()


def get_eve_ng_credentials() -> tuple[str, str]:
    """Get EVE-NG credentials."""
    return get_secrets_manager().get_eve_ng_credentials()


def get_snmp_v3_credentials() -> tuple[str, str, str]:
    """Get SNMPv3 default credentials."""
    return get_secrets_manager().get_snmp_v3_credentials()


def get_mcp_auth_token() -> str:
    """Get MCP authentication token."""
    return get_secrets_manager().get_mcp_auth_token()


def get_admin_password() -> str:
    """Get dashboard admin default password."""
    return get_secrets_manager().get_admin_password()


def get_webhook_urls() -> dict[str, str | None]:
    """Get webhook URLs."""
    return get_secrets_manager().get_webhook_urls()
