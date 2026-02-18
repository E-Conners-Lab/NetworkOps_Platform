"""
MemoryAwareToolManager - Automatic context injection for MCP tools.

Wraps FastMCP's ToolManager to inject relevant context before tool calls
and record results after execution.

Enhanced with error-learning feedback system that injects corrections
from past mistakes into future tool calls.
"""

import time
import asyncio
import json
from typing import Any, Optional

from .store import MemoryStore
from .models import ContextItem, FeedbackRecord


class MemoryAwareToolManager:
    """
    Wrapper that adds memory capabilities to MCP tool execution.

    Automatically:
    - Injects relevant context before tool calls
    - Records tool results for future retrieval
    - Maintains conversation continuity across sessions
    """

    def __init__(
        self,
        memory_store: MemoryStore,
        context_limit: int = 5,
        time_window_minutes: int = 60,
        record_all_calls: bool = True
    ):
        """
        Initialize memory-aware tool manager.

        Args:
            memory_store: MemoryStore instance for persistence
            context_limit: Max context items to inject per call
            time_window_minutes: How far back to look for context
            record_all_calls: Whether to record all tool calls
        """
        self.memory_store = memory_store
        self.context_limit = context_limit
        self.time_window_minutes = time_window_minutes
        self.record_all_calls = record_all_calls

        # Track ongoing operations for deduplication
        self._active_calls: set[str] = set()

    async def get_context_for_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any]
    ) -> list[ContextItem]:
        """
        Retrieve relevant context for a tool call.

        Args:
            tool_name: Name of the tool being called
            arguments: Tool arguments

        Returns:
            List of relevant context items
        """
        device_name = arguments.get("device_name")

        return await self.memory_store.get_relevant_context(
            tool_name=tool_name,
            device_name=device_name,
            limit=self.context_limit,
            time_window_minutes=self.time_window_minutes
        )

    async def get_feedback_for_tool(
        self,
        tool_name: str,
        device_name: Optional[str] = None,
        limit: int = 3
    ) -> list[dict[str, Any]]:
        """
        Retrieve relevant feedback/corrections for a tool call.

        Args:
            tool_name: Name of the tool being called
            device_name: Device being operated on (optional)
            limit: Max feedback items to return

        Returns:
            List of feedback records with corrections/resolutions
        """
        try:
            return await self.memory_store.get_relevant_feedback(
                tool_name=tool_name,
                device_name=device_name,
                limit=limit
            )
        except Exception as e:
            # Don't fail tool calls if feedback retrieval fails
            print(f"Feedback retrieval error: {e}")
            return []

    def format_context_for_injection(
        self,
        context_items: list[ContextItem],
        feedback_items: Optional[list[dict[str, Any]]] = None
    ) -> Optional[str]:
        """
        Format context items and feedback for display.

        Returns None if no context available.
        """
        lines = []

        # Add feedback corrections first (most actionable)
        if feedback_items:
            lines.append("[Learned Corrections]")
            for fb in feedback_items:
                hint = self._format_feedback_hint(fb)
                if hint:
                    lines.append(f"  ⚠ {hint}")

        # Add memory context
        if context_items:
            lines.append("[Memory Context]")
            for item in context_items:
                lines.append(f"  - {item.to_display()}")

        if not lines:
            return None

        return "\n".join(lines)

    def _format_feedback_hint(self, feedback: dict[str, Any]) -> Optional[str]:
        """Format a feedback record as an actionable hint."""
        hint_parts = []

        tool = feedback.get("tool_name", "")
        device = feedback.get("device_name")
        error_type = feedback.get("error_type")
        resolution = feedback.get("resolution")
        correction = feedback.get("correction")
        severity = feedback.get("severity", "medium")

        # Build hint
        if device:
            hint_parts.append(f"{tool} on {device}")
        else:
            hint_parts.append(tool)

        if error_type:
            hint_parts.append(f"previously failed ({error_type})")

        # Add the fix
        if resolution:
            hint_parts.append(f"→ Fix: {resolution}")
        elif correction:
            hint_parts.append(f"→ Should: {correction}")

        if not hint_parts:
            return None

        # Add severity indicator for high/critical
        prefix = ""
        if severity == "critical":
            prefix = "[CRITICAL] "
        elif severity == "high":
            prefix = "[HIGH] "

        return prefix + ". ".join(hint_parts)

    async def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any,
        duration_ms: int,
        status: str = "success"
    ):
        """
        Record a tool call for future context.

        Fire-and-forget - doesn't block the response.
        """
        # Extract device name
        device_name = arguments.get("device_name")

        # Generate result summary
        result_summary = self._summarize_result(result, tool_name)

        # Record asynchronously
        try:
            await self.memory_store.record_tool_call(
                tool_name=tool_name,
                device_name=device_name,
                arguments=arguments,
                result_summary=result_summary,
                duration_ms=duration_ms,
                status=status
            )
        except Exception as e:
            # Don't fail the tool call if recording fails
            print(f"Memory recording error: {e}")

    def _summarize_result(self, result: Any, tool_name: str) -> str:
        """
        Generate a concise summary of a tool result.

        Extracts key information for context injection.
        """
        if result is None:
            return f"{tool_name} completed"

        # Try to parse as JSON
        if isinstance(result, str):
            try:
                data = json.loads(result)
            except json.JSONDecodeError:
                # Truncate long string results
                if len(result) > 200:
                    return result[:200] + "..."
                return result
        else:
            data = result

        # Extract summary based on tool type
        if isinstance(data, dict):
            # Health check results
            if "status" in data:
                status = data.get("status", "unknown")
                device = data.get("device", "")
                return f"{device} status: {status}"

            # Summary fields
            if "summary" in data:
                summary = data["summary"]
                if isinstance(summary, dict):
                    return json.dumps(summary)
                return str(summary)[:200]

            # Health check all
            if "healthy" in data:
                return f"Healthy: {data.get('healthy', 0)}, Degraded: {data.get('degraded', 0)}"

            # Command output
            if "output" in data:
                output = data["output"]
                if len(output) > 200:
                    return output[:200] + "..."
                return output

        # Default: stringify and truncate
        result_str = str(data)
        if len(result_str) > 200:
            return result_str[:200] + "..."
        return result_str


def create_memory_hooks(memory_manager: MemoryAwareToolManager):
    """
    Create pre/post hooks for tool execution.

    Returns tuple of (pre_hook, post_hook) functions.

    The pre_hook injects:
    - Learned corrections from past mistakes (feedback system)
    - Recent context (tool calls, device states)
    """
    async def pre_hook(tool_name: str, arguments: dict) -> Optional[str]:
        """Called before tool execution. Returns context to inject."""
        device_name = arguments.get("device_name")

        # Fetch context and feedback in parallel
        context_task = memory_manager.get_context_for_tool(tool_name, arguments)
        feedback_task = memory_manager.get_feedback_for_tool(tool_name, device_name)

        context_items, feedback_items = await asyncio.gather(
            context_task, feedback_task
        )

        return memory_manager.format_context_for_injection(
            context_items, feedback_items
        )

    async def post_hook(
        tool_name: str,
        arguments: dict,
        result: Any,
        duration_ms: int,
        error: Optional[Exception] = None
    ):
        """Called after tool execution. Records the result."""
        status = "error" if error else "success"
        # Fire and forget
        asyncio.create_task(
            memory_manager.record_tool_call(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                duration_ms=duration_ms,
                status=status
            )
        )

    return pre_hook, post_hook


def wrap_tool_function(func, memory_manager: MemoryAwareToolManager):
    """
    Wrap a tool function with memory capabilities.

    This decorator adds context injection (including learned corrections)
    and result recording.
    """
    import functools

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        tool_name = func.__name__
        device_name = kwargs.get("device_name")

        # Get context and feedback in parallel
        context_task = memory_manager.get_context_for_tool(tool_name, kwargs)
        feedback_task = memory_manager.get_feedback_for_tool(tool_name, device_name)

        context_items, feedback_items = await asyncio.gather(
            context_task, feedback_task
        )

        # Log context (for debugging/visibility)
        if context_items or feedback_items:
            context_str = memory_manager.format_context_for_injection(
                context_items, feedback_items
            )
            if context_str:
                print(context_str)

        # Execute tool
        start_time = time.time()
        error = None
        result = None

        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            error = e
            raise
        finally:
            duration_ms = int((time.time() - start_time) * 1000)

            # Record (fire and forget)
            asyncio.create_task(
                memory_manager.record_tool_call(
                    tool_name=tool_name,
                    arguments=kwargs,
                    result=result,
                    duration_ms=duration_ms,
                    status="error" if error else "success"
                )
            )

    return wrapper
