"""
Tests for MCP tools registry validation.

Ensures no duplicate tool names and consistent tool signatures across all modules.
"""
import pytest


class TestToolsRegistry:
    """Validate TOOLS registry across all mcp_tools modules."""

    def test_no_duplicate_tool_names_in_operations(self):
        """Ensure no duplicate tool names in operations TOOLS."""
        from mcp_tools.operations import TOOLS

        names = [t["name"] for t in TOOLS]
        duplicates = [n for n in names if names.count(n) > 1]

        assert len(names) == len(set(names)), f"Duplicate tool names: {set(duplicates)}"

    def test_operations_tools_have_consistent_signature(self):
        """Each operations tool must have fn, name, and category."""
        from mcp_tools.operations import TOOLS

        for tool in TOOLS:
            assert "fn" in tool and callable(tool["fn"]), f"Tool missing callable 'fn': {tool}"
            assert "name" in tool and isinstance(tool["name"], str), f"Tool missing 'name': {tool}"
            assert "category" in tool and isinstance(tool["category"], str), f"Tool missing 'category': {tool}"

    def test_operations_tools_count(self):
        """Verify expected number of operations tools."""
        from mcp_tools.operations import TOOLS

        # 3 (interfaces) + 2 (health) + 4 (diagnostics) + 2 (routing) + 4 (sessions) + 2 (bulk) = 17
        assert len(TOOLS) == 17, f"Expected 17 tools, got {len(TOOLS)}"

    def test_submodule_tools_sum_equals_facade(self):
        """Verify submodule TOOLS sum equals facade TOOLS count."""
        from mcp_tools.interfaces import TOOLS as interfaces
        from mcp_tools.health import TOOLS as health
        from mcp_tools.diagnostics import TOOLS as diagnostics
        from mcp_tools.routing import TOOLS as routing
        from mcp_tools.sessions import TOOLS as sessions
        from mcp_tools.bulk import TOOLS as bulk
        from mcp_tools.operations import TOOLS as facade

        submodule_total = (
            len(interfaces) + len(health) + len(diagnostics) +
            len(routing) + len(sessions) + len(bulk)
        )

        assert submodule_total == len(facade), (
            f"Submodule total ({submodule_total}) != facade ({len(facade)})"
        )

    def test_no_duplicate_tool_names_across_all_mcp_tools(self):
        """Ensure no duplicate tool names across ALL mcp_tools modules."""
        import importlib
        import pkgutil
        import mcp_tools

        all_names = []

        for importer, modname, ispkg in pkgutil.iter_modules(mcp_tools.__path__):
            if modname.startswith('_'):
                continue
            try:
                mod = importlib.import_module(f'mcp_tools.{modname}')
                if hasattr(mod, 'TOOLS'):
                    for tool in mod.TOOLS:
                        all_names.append((modname, tool.get("name", "unknown")))
            except ImportError:
                pass  # Skip modules that can't be imported

        # Check for duplicates (same name in different modules is OK for facade re-exports)
        name_counts = {}
        for modname, name in all_names:
            if modname == "operations":
                continue  # Skip facade as it re-exports
            if name not in name_counts:
                name_counts[name] = []
            name_counts[name].append(modname)

        duplicates = {name: mods for name, mods in name_counts.items() if len(mods) > 1}
        assert not duplicates, f"Duplicate tool names across modules: {duplicates}"


class TestAuthExports:
    """Validate auth package exports."""

    def test_all_exports_importable(self):
        """Verify every __all__ symbol can be imported."""
        import dashboard.auth

        for name in dashboard.auth.__all__:
            obj = getattr(dashboard.auth, name, None)
            assert obj is not None, f"Failed to import {name} from dashboard.auth"

    def test_auth_exports_count(self):
        """Verify expected number of auth exports."""
        import dashboard.auth

        # Should have 56 exports based on __all__
        assert len(dashboard.auth.__all__) >= 50, (
            f"Expected at least 50 exports, got {len(dashboard.auth.__all__)}"
        )

    def test_key_auth_functions_available(self):
        """Verify key auth functions are exported."""
        from dashboard.auth import (
            jwt_required,
            permission_required,
            admin_required,
            authenticate_user,
            create_token,
            decode_token,
            get_user,
            create_user,
            get_user_permissions,
            validate_password_strength,
        )

        assert callable(jwt_required)
        assert callable(authenticate_user)
        assert callable(create_token)
