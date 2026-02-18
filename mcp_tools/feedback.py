"""
Feedback MCP Tools - Error Learning System.

Provides tools for recording, searching, and analyzing feedback
on tool executions to enable learning from mistakes.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_memory_store():
    """Get the memory store singleton.

    Uses the default MemoryStore path (data/networkops.db) instead of
    a hardcoded memory.db override, so feedback data lives in the
    consolidated database.
    """
    from memory.store import MemoryStore
    from pathlib import Path

    data_dir = Path(__file__).parent.parent / "data"
    return MemoryStore(
        chromadb_path=data_dir / "chromadb"
    )


async def feedback_record(
    tool_name: str,
    correct: bool,
    device_name: Optional[str] = None,
    error_type: Optional[str] = None,
    original_error: Optional[str] = None,
    correction: Optional[str] = None,
    resolution: Optional[str] = None,
    severity: str = "medium"
) -> str:
    """
    Record feedback on a tool execution for error learning.

    Use this to record whether an action was correct or incorrect,
    and if incorrect, what the fix was. This enables learning from
    mistakes and injecting relevant corrections into future context.

    Args:
        tool_name: Name of the tool (e.g., "send_command", "health_check")
        correct: True if the action was correct, False if it failed/was wrong
        device_name: Device involved (e.g., "R1", "Switch-R1")
        error_type: Category of error (connection, syntax, logic, timeout, permission)
        original_error: Description of what went wrong
        correction: What should have been done instead
        resolution: How the issue was eventually fixed
        severity: low, medium, high, or critical

    Returns:
        JSON with record ID and confirmation

    Examples:
        # Record a successful action
        feedback_record("health_check", True, device_name="R1")

        # Record a failed action with resolution
        feedback_record(
            "send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            original_error="Connection refused",
            resolution="Run health_check first to verify device is reachable"
        )
    """
    store = _get_memory_store()

    try:
        record_id = await store.record_feedback(
            tool_name=tool_name,
            correct=correct,
            device_name=device_name,
            error_type=error_type,
            original_error=original_error,
            correction=correction,
            resolution=resolution,
            severity=severity
        )

        return json.dumps({
            "status": "recorded",
            "feedback_id": record_id,
            "tool_name": tool_name,
            "correct": correct,
            "message": "Feedback recorded for error learning"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to record feedback: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e)
        })


async def feedback_search(
    tool_name: str,
    device_name: Optional[str] = None,
    error_type: Optional[str] = None,
    limit: int = 5
) -> str:
    """
    Search for relevant feedback/corrections for a tool.

    Use this before executing a tool to see if there are known
    issues or learned corrections that might be relevant.

    Args:
        tool_name: Name of the tool to search feedback for
        device_name: Filter by device (optional)
        error_type: Filter by error type (optional)
        limit: Maximum results to return (default: 5)

    Returns:
        JSON with relevant feedback records including corrections

    Examples:
        # Find past issues with send_command on R1
        feedback_search("send_command", device_name="R1")

        # Find all connection errors with health_check
        feedback_search("health_check", error_type="connection")
    """
    store = _get_memory_store()

    try:
        results = await store.get_relevant_feedback(
            tool_name=tool_name,
            device_name=device_name,
            error_type=error_type,
            limit=limit
        )

        # Format results with helpful hints
        formatted = []
        for r in results:
            item = {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "tool_name": r["tool_name"],
                "device_name": r["device_name"],
                "error_type": r["error_type"],
                "severity": r["severity"]
            }

            if r["resolution"]:
                item["hint"] = f"Fix: {r['resolution']}"
            elif r["correction"]:
                item["hint"] = f"Should: {r['correction']}"

            if r["original_error"]:
                item["original_error"] = r["original_error"]

            formatted.append(item)

        return json.dumps({
            "tool_name": tool_name,
            "device_name": device_name,
            "count": len(formatted),
            "feedback": formatted,
            "message": f"Found {len(formatted)} relevant feedback records"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search feedback: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e)
        })


async def feedback_stats(days: int = 30) -> str:
    """
    Get feedback statistics for analysis.

    Shows error patterns by tool and error type to identify
    areas that need improvement.

    Args:
        days: Number of days to analyze (default: 30)

    Returns:
        JSON with feedback statistics including:
        - Total feedback count (correct vs errors)
        - Errors by tool
        - Errors by type
        - Unlearned corrections count
    """
    store = _get_memory_store()

    try:
        stats = await store.get_feedback_stats(days=days)

        return json.dumps({
            "period_days": stats["period_days"],
            "summary": {
                "total_feedback": stats["totals"]["total"] or 0,
                "correct": stats["totals"]["correct_count"] or 0,
                "errors": stats["totals"]["error_count"] or 0,
                "accuracy_pct": round(
                    (stats["totals"]["correct_count"] or 0) /
                    max(stats["totals"]["total"] or 1, 1) * 100, 1
                )
            },
            "errors_by_tool": stats["by_tool"],
            "errors_by_type": stats["by_error_type"],
            "unlearned_corrections": stats["unlearned_corrections"],
            "message": "Use unlearned corrections to improve context injection"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get feedback stats: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e)
        })


async def feedback_learn(feedback_id: int) -> str:
    """
    Mark a feedback record as learned/incorporated.

    Call this after incorporating a correction into the system
    to track which feedback has been processed.

    Args:
        feedback_id: ID of the feedback record to mark as learned

    Returns:
        JSON with confirmation
    """
    store = _get_memory_store()

    try:
        success = await store.mark_feedback_learned(feedback_id)

        if success:
            return json.dumps({
                "status": "success",
                "feedback_id": feedback_id,
                "message": "Feedback marked as learned"
            })
        else:
            return json.dumps({
                "status": "not_found",
                "feedback_id": feedback_id,
                "message": "Feedback record not found"
            })

    except Exception as e:
        logger.error(f"Failed to mark feedback as learned: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e)
        })


# Tool definitions for MCP registration
TOOLS = [
    {"fn": feedback_record, "name": "feedback_record", "category": "memory"},
    {"fn": feedback_search, "name": "feedback_search", "category": "memory"},
    {"fn": feedback_stats, "name": "feedback_stats", "category": "memory"},
    {"fn": feedback_learn, "name": "feedback_learn", "category": "memory"},
]
