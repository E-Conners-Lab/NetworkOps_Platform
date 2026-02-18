"""
Integration tests for MCP tools registry and registration.

Tests:
- Tool registration in MCP server
- Duplicate name detection
- Tool name uniqueness across modules
- Category-based tool listing
- Throttled tool execution end-to-end
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from types import SimpleNamespace


class TestMCPToolRegistry:
    """Tests for the mcp_tools registry system."""

    def test_all_tools_loaded(self):
        """ALL_TOOLS should contain tools from all registered modules."""
        from mcp_tools import ALL_TOOLS

        # Currently only device module is migrated (5 tools)
        assert len(ALL_TOOLS) >= 5
        print(f"\n[Info] Total tools in registry: {len(ALL_TOOLS)}")

    def test_tool_name_uniqueness(self):
        """All tool names must be unique across all modules."""
        from mcp_tools import ALL_TOOLS

        names = [t["name"] for t in ALL_TOOLS]
        duplicates = [n for n in names if names.count(n) > 1]

        assert len(duplicates) == 0, f"Duplicate tool names found: {set(duplicates)}"

    def test_get_tool_functions_returns_callables(self):
        """get_tool_functions should return list of callable functions."""
        from mcp_tools import get_tool_functions

        functions = get_tool_functions()

        assert isinstance(functions, list)
        assert len(functions) > 0
        for fn in functions:
            assert callable(fn), f"Non-callable in tool functions: {fn}"

    def test_list_tools_by_category(self):
        """list_tools_by_category should filter correctly."""
        from mcp_tools import list_tools_by_category

        device_tools = list_tools_by_category("device")
        assert len(device_tools) >= 5  # get_devices, send_command, etc.

        # Non-existent category should return empty
        empty = list_tools_by_category("nonexistent_category")
        assert len(empty) == 0

    def test_get_tool_by_name(self):
        """get_tool_by_name should return tool entry or None."""
        from mcp_tools import get_tool_by_name

        # Existing tool
        tool = get_tool_by_name("get_devices")
        assert tool is not None
        assert tool["name"] == "get_devices"
        assert callable(tool["fn"])

        # Non-existent tool
        missing = get_tool_by_name("nonexistent_tool")
        assert missing is None

    def test_get_categories(self):
        """get_categories should return list of unique categories."""
        from mcp_tools import get_categories

        categories = get_categories()
        assert isinstance(categories, list)
        assert "device" in categories


class TestDuplicateDetection:
    """Tests for duplicate tool name detection at import time."""

    def test_duplicate_detection_raises_error(self):
        """_build_registry should raise ValueError for duplicate names."""
        from mcp_tools import _build_registry

        tools_list_1 = [
            {"fn": lambda: None, "name": "test_tool", "category": "test"},
        ]
        tools_list_2 = [
            {"fn": lambda: None, "name": "test_tool", "category": "test"},  # Duplicate!
        ]

        with pytest.raises(ValueError, match="Duplicate tool name"):
            _build_registry(tools_list_1, tools_list_2)

    def test_same_name_different_category_still_duplicate(self):
        """Tools with same name but different category are still duplicates."""
        from mcp_tools import _build_registry

        tools_list_1 = [
            {"fn": lambda: None, "name": "same_name", "category": "category_a"},
        ]
        tools_list_2 = [
            {"fn": lambda: None, "name": "same_name", "category": "category_b"},
        ]

        with pytest.raises(ValueError, match="Duplicate tool name"):
            _build_registry(tools_list_1, tools_list_2)

    def test_unique_names_succeed(self):
        """_build_registry should succeed with unique tool names."""
        from mcp_tools import _build_registry

        tools_list_1 = [
            {"fn": lambda: None, "name": "tool_a", "category": "test"},
        ]
        tools_list_2 = [
            {"fn": lambda: None, "name": "tool_b", "category": "test"},
        ]

        result = _build_registry(tools_list_1, tools_list_2)
        assert len(result) == 2
        assert {t["name"] for t in result} == {"tool_a", "tool_b"}


class TestConcurrencyDiagnostics:
    """Tests for concurrency behavior of throttled tools."""

    async def test_concurrency_diagnostics(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports, timed_run):
        """Execute multiple throttled tasks and measure concurrency behavior."""
        from mcp_tools.device import send_command
        from mcp_tools._shared import get_semaphore, reset_semaphore

        # Reset to ensure clean state
        reset_semaphore()
        sem = get_semaphore()

        concurrent_active = 0
        max_concurrent = 0

        async def monitored_task(i):
            nonlocal concurrent_active, max_concurrent
            async with sem:
                concurrent_active += 1
                max_concurrent = max(max_concurrent, concurrent_active)
                await asyncio.sleep(0.02)
                result = await send_command("R1", f"ping {i}")
                concurrent_active -= 1
                return result

        timed_run.start()
        outputs = await asyncio.gather(*(monitored_task(i) for i in range(20)))
        timed_run.stop()

        print(f"\n[Diagnostic] Max concurrent tasks: {max_concurrent}")
        print(f"[Diagnostic] Total duration: {timed_run.duration:.3f}s")

        # Verify throttling behavior
        assert timed_run.duration > 0
        assert max_concurrent <= 100  # Default semaphore limit

        # Cleanup
        reset_semaphore()


class TestToolMetadata:
    """Tests for tool entry metadata structure."""

    def test_all_tools_have_required_fields(self):
        """Every tool entry must have fn, name, and category."""
        from mcp_tools import ALL_TOOLS

        required_fields = {"fn", "name", "category"}

        for tool in ALL_TOOLS:
            missing = required_fields - set(tool.keys())
            assert len(missing) == 0, f"Tool {tool.get('name', 'UNKNOWN')} missing fields: {missing}"

    def test_tool_functions_have_docstrings(self):
        """Tool functions should have docstrings for MCP tool descriptions."""
        from mcp_tools import ALL_TOOLS

        missing_docs = []
        for tool in ALL_TOOLS:
            fn = tool["fn"]
            if not fn.__doc__:
                missing_docs.append(tool["name"])

        if missing_docs:
            print(f"\n[Warning] Tools without docstrings: {missing_docs}")
        # Not failing for now, but log warning


class TestAllThrottledToolsConcurrency:
    """Stress test for all throttled tools from the registry."""

    async def test_all_send_tools_concurrency(self, mock_devices, mock_scrapli_device, patch_mcp_device_imports, timed_run):
        """Execute all send_* tools in parallel to verify throttling."""
        from mcp_tools import ALL_TOOLS

        # Find all tools that start with "send_" (typically throttled)
        throttled_tools = [
            t for t in ALL_TOOLS
            if t["fn"].__name__.startswith("send_")
        ]

        if not throttled_tools:
            pytest.skip("No throttled tools found")

        async def run_tool(tool_entry, idx):
            fn = tool_entry["fn"]
            # Most send_* tools take (device_name, command)
            return await fn("R1", f"mock-cmd-{idx}")

        timed_run.start()
        # Run each throttled tool 3 times
        outputs = await asyncio.gather(
            *(run_tool(t, i) for i, t in enumerate(throttled_tools * 3)),
            return_exceptions=True
        )
        timed_run.stop()

        print(f"\n[Diagnostic] Ran {len(outputs)} throttled tool calls in {timed_run.duration:.3f}s")

        # Check for exceptions
        exceptions = [o for o in outputs if isinstance(o, Exception)]
        assert len(exceptions) == 0, f"Exceptions during execution: {exceptions}"


class TestModuleImports:
    """Tests for module import behavior."""

    def test_device_module_imports_cleanly(self):
        """device module should import without errors."""
        # This implicitly tests for circular import issues
        from mcp_tools.device import TOOLS, get_devices, send_command

        assert len(TOOLS) == 5
        assert callable(get_devices)
        assert callable(send_command)

    def test_shared_module_exports(self):
        """_shared module should export expected utilities."""
        from mcp_tools._shared import (
            get_semaphore,
            reset_semaphore,
            throttled,
            throttled_decorator,
            set_memory_store,
            get_memory_store,
            record_to_memory,
            MAX_CONCURRENT_CONNECTIONS,
        )

        assert callable(get_semaphore)
        assert callable(reset_semaphore)
        assert callable(throttled)
        assert callable(throttled_decorator)
        assert callable(set_memory_store)
        assert callable(get_memory_store)
        assert isinstance(MAX_CONCURRENT_CONNECTIONS, int)

    def test_registry_exports(self):
        """__init__ module should export expected functions."""
        from mcp_tools import (
            ALL_TOOLS,
            get_tool_functions,
            list_tools_by_category,
            get_tool_by_name,
            get_categories,
        )

        assert isinstance(ALL_TOOLS, list)
        assert callable(get_tool_functions)
        assert callable(list_tools_by_category)
        assert callable(get_tool_by_name)
        assert callable(get_categories)
