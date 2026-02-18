"""
Pydantic models for MCP Memory System.
"""

from datetime import datetime
from typing import Optional, Literal, Any

from pydantic import BaseModel, Field

from core.timestamps import now


class ToolCallRecord(BaseModel):
    """Record of a single tool invocation."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=now)
    tool_name: str
    device_name: Optional[str] = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_summary: Optional[str] = None
    duration_ms: Optional[int] = None
    status: Literal["success", "error", "timeout"] = "success"


class DeviceState(BaseModel):
    """Snapshot of device state at a point in time."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=now)
    device_name: str
    state_type: str  # "health_check", "baseline", "netconf_snapshot"
    data: dict[str, Any] = Field(default_factory=dict)
    label: Optional[str] = None  # e.g., "pre-network-isolation"


class ConversationEntry(BaseModel):
    """Summary of a conversation segment."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=now)
    session_id: Optional[str] = None
    summary: str
    tools_used: list[str] = Field(default_factory=list)
    devices_mentioned: list[str] = Field(default_factory=list)


class ContextItem(BaseModel):
    """A single piece of context to be injected into tool calls."""
    id: str
    timestamp: datetime
    item_type: Literal["tool_call", "device_state", "conversation", "event"]
    device: Optional[str] = None
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    relevance_score: float = 0.0
    semantic_score: Optional[float] = None

    def to_display(self) -> str:
        """Format for display in context injection."""
        device_prefix = f"[{self.device}] " if self.device else ""
        time_str = self.timestamp.strftime("%Y-%m-%d %H:%M")
        return f"{device_prefix}{time_str}: {self.content}"


class MemoryQuery(BaseModel):
    """Query parameters for memory retrieval."""
    device_name: Optional[str] = None
    tool_name: Optional[str] = None
    time_window_minutes: int = 60
    limit: int = 5
    include_semantic: bool = True
    semantic_query: Optional[str] = None


class FeedbackRecord(BaseModel):
    """Record of feedback on tool execution - used for error learning."""
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=now)
    tool_call_id: Optional[int] = None  # Links to tool_calls table
    session_id: Optional[str] = None
    tool_name: str
    device_name: Optional[str] = None
    correct: bool  # Was Claude's action correct?
    error_type: Optional[str] = None  # Categorized error (connection, syntax, logic, etc.)
    original_error: Optional[str] = None  # What went wrong
    correction: Optional[str] = None  # What should have happened
    resolution: Optional[str] = None  # How it was eventually fixed
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    learned: bool = False  # Has this been incorporated into context?

    def to_context_hint(self) -> str:
        """Format as a hint for context injection."""
        hint = f"Note: {self.tool_name}"
        if self.device_name:
            hint += f" on {self.device_name}"
        if self.error_type:
            hint += f" previously failed with {self.error_type}"
        if self.resolution:
            hint += f". Fix: {self.resolution}"
        elif self.correction:
            hint += f". Should have: {self.correction}"
        return hint
