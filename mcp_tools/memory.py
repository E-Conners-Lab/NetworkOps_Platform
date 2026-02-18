"""
Memory system MCP tools.

This module provides tools for managing the memory/context system:
- memory_search: Search memory with natural language query
- memory_save: Save a note to memory
- memory_recall_device: Get recent events for a device
- memory_stats: Get memory system statistics
- memory_context: Get context for a tool call
- memory_backup: Create memory database backup
- memory_prune: Prune old records
- memory_repair: Repair memory database
- memory_maintenance: Run full maintenance
"""

import json
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from memory import MemoryStore, MemoryAwareToolManager


# Module-level storage for memory system components
_memory_store: Optional["MemoryStore"] = None
_memory_manager: Optional["MemoryAwareToolManager"] = None


def set_memory_components(store: "MemoryStore", manager: "MemoryAwareToolManager"):
    """
    Initialize the memory components for this module.
    Called by the main MCP server during startup.
    """
    global _memory_store, _memory_manager
    _memory_store = store
    _memory_manager = manager


def get_memory_store() -> "MemoryStore":
    """Get the memory store, raising if not initialized."""
    if _memory_store is None:
        raise RuntimeError("Memory store not initialized. Call set_memory_components() first.")
    return _memory_store


def get_memory_manager() -> "MemoryAwareToolManager":
    """Get the memory manager, raising if not initialized."""
    if _memory_manager is None:
        raise RuntimeError("Memory manager not initialized. Call set_memory_components() first.")
    return _memory_manager


# =============================================================================
# MCP Tool Functions
# =============================================================================

async def memory_search(query: str, limit: int = 5) -> str:
    """
    Search memory with natural language query.

    Use this to find relevant past context, troubleshooting history,
    or previous conversations about specific topics.

    Examples:
    - "NHRP issues" - Find past NHRP troubleshooting
    - "R3 configuration changes" - Find config changes on R3
    - "DMVPN tunnel problems" - Find DMVPN-related history
    """
    store = get_memory_store()
    start = time.time()

    # Try semantic search first
    results = await store.semantic_search(query, limit=limit)

    # If no semantic results, fall back to recent context
    if not results:
        results = await store.get_recent_context(limit=limit)

    elapsed = time.time() - start

    if not results:
        return json.dumps({
            "query": query,
            "results": [],
            "message": "No matching memory found",
            "elapsed_seconds": round(elapsed, 3)
        })

    return json.dumps({
        "query": query,
        "results": [
            {
                "timestamp": item.timestamp.isoformat(),
                "type": item.item_type,
                "device": item.device,
                "content": item.content,
                "relevance": round(item.relevance_score, 2) if item.relevance_score else None
            }
            for item in results
        ],
        "count": len(results),
        "elapsed_seconds": round(elapsed, 3)
    }, indent=2)


async def memory_save(note: str, devices: str = None, topics: str = None) -> str:
    """
    Save a note to memory for later retrieval.

    Use this to record important findings, decisions, or context
    that should be remembered across sessions.

    Args:
        note: The note content to save
        devices: Comma-separated device names (e.g., "R1,R3")
        topics: Comma-separated topics (e.g., "OSPF,troubleshooting")
    """
    store = get_memory_store()

    device_list = [d.strip() for d in devices.split(",")] if devices else []
    topic_list = [t.strip() for t in topics.split(",")] if topics else []

    record_id = await store.save_note(
        note=note,
        devices=device_list,
        topics=topic_list
    )

    return json.dumps({
        "status": "saved",
        "id": record_id,
        "note": note[:100] + "..." if len(note) > 100 else note,
        "devices": device_list,
        "topics": topic_list
    })


async def memory_recall_device(device_name: str, limit: int = 10) -> str:
    """
    Get recent memory entries for a specific device.

    Shows recent tool calls, state changes, and notes related to the device.
    """
    store = get_memory_store()
    start = time.time()

    events = await store.get_device_events(
        device_name=device_name,
        limit=limit,
        time_window_minutes=1440  # Last 24 hours
    )

    elapsed = time.time() - start

    return json.dumps({
        "device": device_name,
        "events": [
            {
                "timestamp": item.timestamp.isoformat(),
                "type": item.item_type,
                "content": item.content,
                "metadata": item.metadata
            }
            for item in events
        ],
        "count": len(events),
        "elapsed_seconds": round(elapsed, 3)
    }, indent=2)


async def memory_stats() -> str:
    """
    Get memory system statistics.

    Shows counts of stored tool calls, device states, and conversations.
    """
    store = get_memory_store()
    stats = await store.get_stats()
    return json.dumps(stats, indent=2)


async def memory_context(tool_name: str, device_name: str = None) -> str:
    """
    Get relevant context for a hypothetical tool call.

    This shows what context would be injected if you were about to
    call the specified tool. Useful for understanding what the
    memory system knows about a device or operation.
    """
    manager = get_memory_manager()

    context_items = await manager.get_context_for_tool(
        tool_name=tool_name,
        arguments={"device_name": device_name} if device_name else {}
    )

    if not context_items:
        return json.dumps({
            "tool_name": tool_name,
            "device_name": device_name,
            "context": [],
            "message": "No relevant context found"
        })

    return json.dumps({
        "tool_name": tool_name,
        "device_name": device_name,
        "context": [
            {
                "timestamp": item.timestamp.isoformat(),
                "type": item.item_type,
                "device": item.device,
                "content": item.content,
                "relevance": round(item.relevance_score, 2)
            }
            for item in context_items
        ],
        "count": len(context_items)
    }, indent=2)


async def memory_backup() -> str:
    """
    Create a backup of the memory database.

    Backups are stored in data/backups/ with timestamps.
    Old backups are automatically cleaned up (keeps last 5 by default).
    """
    store = get_memory_store()

    try:
        backup_path = await store.backup()
        return json.dumps({
            "status": "success",
            "backup_path": str(backup_path),
            "size_bytes": backup_path.stat().st_size
        }, indent=2)
    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": str(e)
        }, indent=2)


async def memory_prune(days: int = None, run_vacuum: bool = True) -> str:
    """
    Prune old records from memory.

    Args:
        days: Delete records older than this many days (default: 30)
        run_vacuum: Whether to vacuum database after pruning (default: True)

    Use this to manually enforce retention or free up space.
    """
    store = get_memory_store()
    results = {}

    # Prune by age
    results["by_age"] = await store.prune_old_records(days)

    # Prune by count
    results["by_count"] = await store.prune_by_count()

    # Vacuum if requested
    if run_vacuum:
        results["vacuum_bytes"] = await store.vacuum()

    total_pruned = (
        sum(results["by_age"].values()) +
        sum(results["by_count"].values())
    )

    return json.dumps({
        "status": "success",
        "total_records_pruned": total_pruned,
        "details": results
    }, indent=2)


async def memory_repair() -> str:
    """
    Attempt to repair the memory database.

    Runs integrity check, rebuilds indexes, and vacuums.
    Use this if you suspect database corruption.
    """
    store = get_memory_store()
    results = await store.repair()
    return json.dumps(results, indent=2)


async def memory_maintenance() -> str:
    """
    Run full maintenance on the memory database.

    Combines pruning (by age and count) and vacuum.
    Safe to run regularly.
    """
    store = get_memory_store()
    results = await store.run_maintenance()
    return json.dumps(results, indent=2)


# =============================================================================
# Tool Registry
# =============================================================================

TOOLS = [
    {"fn": memory_search, "name": "memory_search", "category": "memory"},
    {"fn": memory_save, "name": "memory_save", "category": "memory"},
    {"fn": memory_recall_device, "name": "memory_recall_device", "category": "memory"},
    {"fn": memory_stats, "name": "memory_stats", "category": "memory"},
    {"fn": memory_context, "name": "memory_context", "category": "memory"},
    {"fn": memory_backup, "name": "memory_backup", "category": "memory"},
    {"fn": memory_prune, "name": "memory_prune", "category": "memory"},
    {"fn": memory_repair, "name": "memory_repair", "category": "memory"},
    {"fn": memory_maintenance, "name": "memory_maintenance", "category": "memory"},
]
