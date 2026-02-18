"""Tests for config/vault_client.py — new SecretsManager methods.

All tests run with USE_VAULT=false (the default), so secrets resolve
via environment variables only.  The Vault-first path is tested via
mocked hvac.
"""

import os
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_secrets_manager():
    """Create a fresh SecretsManager (not the singleton) for test isolation."""
    from config.vault_client import SecretsManager, VaultClient
    return SecretsManager(vault_client=VaultClient())


# ---------------------------------------------------------------------------
# get_netbox_token
# ---------------------------------------------------------------------------

class TestGetNetboxToken:
    def test_returns_env_value(self, monkeypatch):
        monkeypatch.setenv("NETBOX_API_TOKEN", "nb-tok-123")
        sm = _fresh_secrets_manager()
        assert sm.get_netbox_token() == "nb-tok-123"

    def test_returns_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("NETBOX_API_TOKEN", raising=False)
        sm = _fresh_secrets_manager()
        assert sm.get_netbox_token() == ""


# ---------------------------------------------------------------------------
# get_siem_credentials
# ---------------------------------------------------------------------------

class TestGetSiemCredentials:
    def test_returns_dict_with_correct_keys(self, monkeypatch):
        monkeypatch.setenv("SIEM_SPLUNK_TOKEN", "splunk-tok")
        monkeypatch.setenv("SIEM_ELASTICSEARCH_PASSWORD", "es-pw")
        monkeypatch.setenv("SIEM_ELASTICSEARCH_API_KEY", "es-key")
        sm = _fresh_secrets_manager()
        creds = sm.get_siem_credentials()
        assert creds == {
            "splunk_token": "splunk-tok",
            "elasticsearch_password": "es-pw",
            "elasticsearch_api_key": "es-key",
        }

    def test_returns_empty_when_unset(self, monkeypatch):
        for var in ("SIEM_SPLUNK_TOKEN", "SIEM_ELASTICSEARCH_PASSWORD", "SIEM_ELASTICSEARCH_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        sm = _fresh_secrets_manager()
        creds = sm.get_siem_credentials()
        assert all(v == "" for v in creds.values())


# ---------------------------------------------------------------------------
# get_eve_ng_credentials
# ---------------------------------------------------------------------------

class TestGetEveNgCredentials:
    def test_returns_env_values(self, monkeypatch):
        monkeypatch.setenv("EVE_NG_USERNAME", "myuser")
        monkeypatch.setenv("EVE_NG_PASSWORD", "mypass")
        sm = _fresh_secrets_manager()
        assert sm.get_eve_ng_credentials() == ("myuser", "mypass")

    def test_returns_defaults_when_unset(self, monkeypatch):
        monkeypatch.delenv("EVE_NG_USERNAME", raising=False)
        monkeypatch.delenv("EVE_NG_PASSWORD", raising=False)
        sm = _fresh_secrets_manager()
        assert sm.get_eve_ng_credentials() == ("admin", "eve")


# ---------------------------------------------------------------------------
# get_snmp_v3_credentials
# ---------------------------------------------------------------------------

class TestGetSnmpV3Credentials:
    def test_returns_env_values(self, monkeypatch):
        monkeypatch.setenv("SNMP_V3_USERNAME", "snmpuser")
        monkeypatch.setenv("SNMP_V3_AUTH_PASSWORD", "authpw")
        monkeypatch.setenv("SNMP_V3_PRIV_PASSWORD", "privpw")
        sm = _fresh_secrets_manager()
        assert sm.get_snmp_v3_credentials() == ("snmpuser", "authpw", "privpw")

    def test_returns_empty_when_unset(self, monkeypatch):
        for var in ("SNMP_V3_USERNAME", "SNMP_V3_AUTH_PASSWORD", "SNMP_V3_PRIV_PASSWORD"):
            monkeypatch.delenv(var, raising=False)
        sm = _fresh_secrets_manager()
        assert sm.get_snmp_v3_credentials() == ("", "", "")


# ---------------------------------------------------------------------------
# get_mcp_auth_token
# ---------------------------------------------------------------------------

class TestGetMcpAuthToken:
    def test_returns_env_value(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_TOKEN", "mcp-tok")
        sm = _fresh_secrets_manager()
        assert sm.get_mcp_auth_token() == "mcp-tok"

    def test_returns_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
        sm = _fresh_secrets_manager()
        assert sm.get_mcp_auth_token() == ""


# ---------------------------------------------------------------------------
# get_admin_password
# ---------------------------------------------------------------------------

class TestGetAdminPassword:
    def test_returns_env_value(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_ADMIN_PASSWORD", "s3cret")
        sm = _fresh_secrets_manager()
        assert sm.get_admin_password() == "s3cret"

    def test_returns_default_admin(self, monkeypatch):
        monkeypatch.delenv("DASHBOARD_ADMIN_PASSWORD", raising=False)
        sm = _fresh_secrets_manager()
        assert sm.get_admin_password() == "admin"


# ---------------------------------------------------------------------------
# get_webhook_urls
# ---------------------------------------------------------------------------

class TestGetWebhookUrls:
    def test_returns_env_values(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/x")
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://teams.example.com/x")
        monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
        monkeypatch.delenv("GENERIC_WEBHOOK_URL", raising=False)
        sm = _fresh_secrets_manager()
        urls = sm.get_webhook_urls()
        assert urls["slack_url"] == "https://hooks.slack.com/x"
        assert urls["teams_url"] == "https://teams.example.com/x"
        assert urls["discord_url"] is None
        assert urls["pagerduty_key"] is None
        assert urls["generic_url"] is None

    def test_returns_none_when_all_unset(self, monkeypatch):
        for var in ("SLACK_WEBHOOK_URL", "TEAMS_WEBHOOK_URL", "DISCORD_WEBHOOK_URL",
                     "PAGERDUTY_ROUTING_KEY", "GENERIC_WEBHOOK_URL"):
            monkeypatch.delenv(var, raising=False)
        sm = _fresh_secrets_manager()
        urls = sm.get_webhook_urls()
        assert all(v is None for v in urls.values())


# ---------------------------------------------------------------------------
# get_api_key — "mcp" key was added to env_map
# ---------------------------------------------------------------------------

class TestGetApiKeyMcp:
    def test_mcp_key(self, monkeypatch):
        monkeypatch.setenv("MCP_AUTH_TOKEN", "mcp-key-123")
        sm = _fresh_secrets_manager()
        assert sm.get_api_key("mcp") == "mcp-key-123"


# ---------------------------------------------------------------------------
# Vault-first lookup (mocked hvac)
# ---------------------------------------------------------------------------

class TestVaultFirstLookup:
    """When USE_VAULT=true and Vault has the secret, env var is not used."""

    def test_vault_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("USE_VAULT", "true")
        monkeypatch.setenv("NETBOX_API_TOKEN", "env-token")

        from config.vault_client import SecretsManager, VaultClient

        mock_client = MagicMock(spec=VaultClient)
        mock_client.is_available.return_value = True
        mock_client.get_secret.return_value = "vault-token"

        sm = SecretsManager(vault_client=mock_client)
        assert sm.get_netbox_token() == "vault-token"
        mock_client.get_secret.assert_called_with("networkops/api_keys", "netbox")

    def test_falls_back_to_env_when_vault_returns_none(self, monkeypatch):
        monkeypatch.setenv("USE_VAULT", "true")
        monkeypatch.setenv("NETBOX_API_TOKEN", "env-token")

        from config.vault_client import SecretsManager, VaultClient

        mock_client = MagicMock(spec=VaultClient)
        mock_client.is_available.return_value = True
        mock_client.get_secret.return_value = None

        sm = SecretsManager(vault_client=mock_client)
        assert sm.get_netbox_token() == "env-token"


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

class TestConvenienceFunctions:
    """Verify module-level functions delegate to singleton."""

    def test_get_netbox_token(self, monkeypatch):
        monkeypatch.setenv("NETBOX_API_TOKEN", "conv-tok")
        # Reset singleton to pick up fresh env
        import config.vault_client as vc
        vc._secrets_manager = None
        assert vc.get_netbox_token() == "conv-tok"
        vc._secrets_manager = None  # clean up

    def test_get_admin_password(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_ADMIN_PASSWORD", "pw123")
        import config.vault_client as vc
        vc._secrets_manager = None
        assert vc.get_admin_password() == "pw123"
        vc._secrets_manager = None
