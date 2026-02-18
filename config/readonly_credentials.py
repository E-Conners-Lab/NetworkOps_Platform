"""
Read-only credential provider for impact analysis.

This module provides ONLY read-only credentials for network devices.
It is intentionally separate from config/devices.py to enforce credential isolation.

SECURITY DESIGN:
- ImpactAnalyzer imports ONLY from this module
- Read-only users are configured on devices with privilege level 1 (show commands only)
- This module does NOT have access to admin credentials
- If ImpactAnalyzer accidentally imports from config.devices, it's a code review failure

DEVICE CONFIGURATION REQUIRED:
    username readonly privilege 1 secret <hash>

    # The user will be able to run show commands but NOT:
    # - Enter config mode (configure terminal)
    # - Enable/disable interfaces
    # - Make any configuration changes
"""

import os
from dataclasses import dataclass
from typing import Protocol

from dotenv import load_dotenv

load_dotenv()


class ReadOnlyCredentialProvider(Protocol):
    """Protocol for read-only credential providers.

    ImpactAnalyzer type-checks against this protocol at initialization.
    Any credential provider must implement these methods.
    """

    def get_username(self) -> str:
        """Get read-only username."""
        ...

    def get_password(self) -> str:
        """Get read-only password."""
        ...

    def get_credentials(self) -> tuple[str, str]:
        """Get (username, password) tuple."""
        ...

    def is_read_only(self) -> bool:
        """Return True to confirm this is a read-only provider.

        This is a marker method that ImpactAnalyzer checks at runtime.
        """
        ...


@dataclass(frozen=True)
class StaticReadOnlyCredentials:
    """Read-only credentials loaded from environment variables.

    Environment variables:
        READONLY_USERNAME: Username for read-only access (default: "readonly")
        READONLY_PASSWORD: Password for read-only access (required in production)

    Usage:
        from config.readonly_credentials import get_readonly_credentials

        provider = get_readonly_credentials()
        username, password = provider.get_credentials()
    """

    username: str
    password: str

    def get_username(self) -> str:
        """Get read-only username."""
        return self.username

    def get_password(self) -> str:
        """Get read-only password."""
        return self.password

    def get_credentials(self) -> tuple[str, str]:
        """Get (username, password) tuple."""
        return self.username, self.password

    def is_read_only(self) -> bool:
        """Confirm this is a read-only credential provider."""
        return True


class VaultReadOnlyCredentials:
    """Read-only credentials from HashiCorp Vault with .env fallback.

    Vault path: networkops/readonly_credentials
    Keys: username, password

    Falls back to READONLY_USERNAME/READONLY_PASSWORD env vars if Vault unavailable.
    """

    def __init__(self):
        self._username: str | None = None
        self._password: str | None = None
        self._loaded = False

    def _load(self) -> None:
        """Load credentials from Vault or environment."""
        if self._loaded:
            return

        # Try Vault first
        try:
            from config.vault_client import get_secrets_manager
            secrets = get_secrets_manager()

            if secrets.is_vault_available():
                vault_username = secrets._vault.get_secret(
                    "networkops/readonly_credentials", "username"
                )
                vault_password = secrets._vault.get_secret(
                    "networkops/readonly_credentials", "password"
                )

                if vault_username and vault_password:
                    self._username = vault_username
                    self._password = vault_password
                    self._loaded = True
                    return
        except Exception:
            pass

        # Fall back to environment variables
        self._username = os.getenv("READONLY_USERNAME", "readonly")
        self._password = os.getenv("READONLY_PASSWORD", "")
        self._loaded = True

    def get_username(self) -> str:
        """Get read-only username."""
        self._load()
        return self._username or "readonly"

    def get_password(self) -> str:
        """Get read-only password."""
        self._load()
        return self._password or ""

    def get_credentials(self) -> tuple[str, str]:
        """Get (username, password) tuple."""
        return self.get_username(), self.get_password()

    def is_read_only(self) -> bool:
        """Confirm this is a read-only credential provider."""
        return True


# Module-level singleton
_readonly_credentials: VaultReadOnlyCredentials | None = None


def get_readonly_credentials() -> VaultReadOnlyCredentials:
    """Get the read-only credential provider singleton.

    Returns:
        VaultReadOnlyCredentials instance (with .env fallback)
    """
    global _readonly_credentials
    if _readonly_credentials is None:
        _readonly_credentials = VaultReadOnlyCredentials()
    return _readonly_credentials


def get_readonly_username() -> str:
    """Convenience function: get read-only username."""
    return get_readonly_credentials().get_username()


def get_readonly_password() -> str:
    """Convenience function: get read-only password."""
    return get_readonly_credentials().get_password()


def validate_credential_provider(provider: object) -> bool:
    """Validate that a credential provider implements ReadOnlyCredentialProvider.

    Args:
        provider: Object to validate

    Returns:
        True if provider is a valid read-only credential provider

    Raises:
        TypeError: If provider doesn't implement required methods
    """
    required_methods = ['get_username', 'get_password', 'get_credentials', 'is_read_only']

    for method in required_methods:
        if not hasattr(provider, method) or not callable(getattr(provider, method)):
            raise TypeError(
                f"Credential provider must implement {method}(). "
                f"Got {type(provider).__name__} which is missing {method}."
            )

    # Check that is_read_only() returns True
    if not provider.is_read_only():
        raise TypeError(
            f"Credential provider {type(provider).__name__}.is_read_only() returned False. "
            "ImpactAnalyzer requires a read-only credential provider."
        )

    return True
