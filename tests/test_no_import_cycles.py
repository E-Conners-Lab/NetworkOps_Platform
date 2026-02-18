"""
Tests to detect circular import issues in refactored modules.

These tests iterate over all submodules to catch hidden import cycles
that might not be apparent when importing only specific symbols.
"""
import importlib
import pkgutil

import pytest


class TestAuthImportCycles:
    """Test that all auth submodules can be imported independently."""

    def test_all_auth_submodules_importable(self):
        """Iterate over all auth submodules to catch hidden cycles."""
        import dashboard.auth as auth_pkg

        imported = []
        errors = []

        for importer, modname, ispkg in pkgutil.iter_modules(auth_pkg.__path__):
            try:
                mod = importlib.import_module(f"dashboard.auth.{modname}")
                imported.append(modname)
                assert mod is not None
            except Exception as e:
                errors.append(f"{modname}: {e}")

        assert not errors, f"Failed to import auth submodules:\n" + "\n".join(errors)
        assert len(imported) >= 10, f"Expected at least 10 auth submodules, got {len(imported)}"

    def test_auth_types_no_dependencies(self):
        """types.py should have no auth submodule dependencies."""
        # This import should work without importing other auth modules
        from dashboard.auth.types import UserInfo, TokenPayload

        assert UserInfo is not None
        assert TokenPayload is not None

    def test_auth_config_no_dependencies(self):
        """config.py should have no auth submodule dependencies."""
        from dashboard.auth.config import JWT_SECRET, LOCKOUT_THRESHOLD

        assert JWT_SECRET is not None
        assert LOCKOUT_THRESHOLD is not None

    def test_auth_facade_imports_all(self):
        """Facade should successfully import all submodules."""
        import dashboard.auth

        # Should have key attributes from each submodule
        assert hasattr(dashboard.auth, 'jwt_required')  # decorators
        assert hasattr(dashboard.auth, 'create_token')  # tokens
        assert hasattr(dashboard.auth, 'authenticate_user')  # identity
        assert hasattr(dashboard.auth, 'get_user_permissions')  # permissions
        assert hasattr(dashboard.auth, 'hash_password')  # passwords
        assert hasattr(dashboard.auth, 'create_mfa_token')  # mfa


class TestMcpToolsImportCycles:
    """Test that all mcp_tools submodules can be imported independently."""

    def test_all_mcp_tools_submodules_importable(self):
        """Iterate over all mcp_tools submodules."""
        import mcp_tools

        imported = []
        errors = []

        for importer, modname, ispkg in pkgutil.iter_modules(mcp_tools.__path__):
            if modname.startswith('_'):
                continue  # Skip private modules
            try:
                mod = importlib.import_module(f"mcp_tools.{modname}")
                imported.append(modname)
                assert mod is not None
            except Exception as e:
                errors.append(f"{modname}: {e}")

        assert not errors, f"Failed to import mcp_tools submodules:\n" + "\n".join(errors)
        assert len(imported) >= 20, f"Expected at least 20 mcp_tools submodules, got {len(imported)}"

    def test_operations_submodules_independent(self):
        """Each operations submodule should import independently."""
        submodules = [
            "mcp_tools._ops_helpers",
            "mcp_tools.interfaces",
            "mcp_tools.health",
            "mcp_tools.diagnostics",
            "mcp_tools.routing",
            "mcp_tools.sessions",
            "mcp_tools.bulk",
        ]

        for modname in submodules:
            mod = importlib.import_module(modname)
            assert mod is not None, f"Failed to import {modname}"

    def test_operations_facade_combines_tools(self):
        """Operations facade should combine all submodule TOOLS."""
        from mcp_tools.operations import TOOLS

        # Should have tools from all submodules
        tool_names = [t["name"] for t in TOOLS]

        # Check for at least one tool from each submodule
        assert "get_interface_status" in tool_names  # interfaces
        assert "linux_health_check" in tool_names  # health
        assert "get_arp_table" in tool_names  # diagnostics
        assert "get_routing_table" in tool_names  # routing
        assert "get_active_sessions" in tool_names  # sessions
        assert "bulk_command" in tool_names  # bulk


class TestCrossModuleImports:
    """Test that cross-module imports work correctly."""

    def test_api_server_can_import_auth(self):
        """api_server imports from dashboard.auth should work."""
        from dashboard.auth import jwt_required, admin_required, init_database

        assert callable(jwt_required)
        assert callable(admin_required)
        assert callable(init_database)

    def test_routes_can_import_auth_decorators(self):
        """Route modules should be able to import auth decorators."""
        from dashboard.auth import (
            jwt_required,
            permission_required,
            admin_required,
            role_required,
        )

        # All should be decorators (functions)
        assert callable(jwt_required)
        assert callable(permission_required)
        assert callable(admin_required)
        assert callable(role_required)
