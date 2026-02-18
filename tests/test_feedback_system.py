"""
Tests for Error-Learning Feedback System.

Validates:
1. FeedbackRecord model
2. Database schema and operations
3. MCP tools (feedback_record, feedback_search, feedback_stats, feedback_learn)
4. Context injection enhancement with learned corrections
"""
import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from datetime import datetime


class TestFeedbackRecordModel:
    """Test the FeedbackRecord Pydantic model."""

    def test_model_creation_minimal(self):
        """Create feedback record with minimal fields."""
        from memory.models import FeedbackRecord

        fb = FeedbackRecord(
            tool_name="health_check",
            correct=True
        )

        assert fb.tool_name == "health_check"
        assert fb.correct is True
        assert fb.severity == "medium"  # default
        assert fb.learned is False  # default

    def test_model_creation_full(self):
        """Create feedback record with all fields."""
        from memory.models import FeedbackRecord

        fb = FeedbackRecord(
            tool_name="send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            original_error="Connection refused",
            correction="Use health_check first",
            resolution="Run health_check to verify device is reachable",
            severity="high"
        )

        assert fb.tool_name == "send_command"
        assert fb.correct is False
        assert fb.device_name == "R1"
        assert fb.error_type == "connection"
        assert fb.severity == "high"

    def test_to_context_hint_with_resolution(self):
        """Test context hint formatting with resolution."""
        from memory.models import FeedbackRecord

        fb = FeedbackRecord(
            tool_name="send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            resolution="Run health_check first"
        )

        hint = fb.to_context_hint()
        assert "send_command" in hint
        assert "R1" in hint
        assert "connection" in hint
        assert "Run health_check first" in hint

    def test_to_context_hint_with_correction(self):
        """Test context hint formatting with correction only."""
        from memory.models import FeedbackRecord

        fb = FeedbackRecord(
            tool_name="backup_config",
            correct=False,
            correction="Verify write access before backup"
        )

        hint = fb.to_context_hint()
        assert "backup_config" in hint
        assert "Should have:" in hint


class TestFeedbackDatabaseSchema:
    """Test the feedback database schema and operations."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing."""
        import sqlite3
        from memory.store import MemoryStore

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_memory.db"
            chromadb_path = Path(tmpdir) / "test_chromadb"
            # Initialize store to create tables
            MemoryStore(db_path=db_path, chromadb_path=chromadb_path)
            # Return connection for schema verification
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            yield conn
            conn.close()

    def test_feedback_table_created(self, temp_db):
        """Verify feedback table is created with correct schema."""
        cursor = temp_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'"
        )
        assert cursor.fetchone() is not None

    def test_feedback_table_columns(self, temp_db):
        """Verify feedback table has expected columns."""
        cursor = temp_db.execute("PRAGMA table_info(feedback)")
        columns = {row[1] for row in cursor.fetchall()}

        expected = {
            "id", "timestamp", "tool_call_id", "session_id",
            "tool_name", "device_name", "correct", "error_type",
            "original_error", "correction", "resolution", "severity", "learned"
        }
        assert expected.issubset(columns)


class TestFeedbackStoreOperations:
    """Test MemoryStore feedback operations."""

    @pytest.fixture
    def temp_store(self):
        """Create a temporary MemoryStore for testing."""
        from memory.store import MemoryStore

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_memory.db"
            chromadb_path = Path(tmpdir) / "test_chromadb"
            store = MemoryStore(db_path=db_path, chromadb_path=chromadb_path)
            yield store

    @pytest.mark.asyncio
    async def test_record_feedback_correct(self, temp_store):
        """Test recording successful feedback."""
        record_id = await temp_store.record_feedback(
            tool_name="health_check",
            correct=True,
            device_name="R1"
        )

        assert record_id > 0

    @pytest.mark.asyncio
    async def test_record_feedback_error(self, temp_store):
        """Test recording error feedback with resolution."""
        record_id = await temp_store.record_feedback(
            tool_name="send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            original_error="Connection refused",
            resolution="Run health_check first to verify connectivity"
        )

        assert record_id > 0

    @pytest.mark.asyncio
    async def test_get_relevant_feedback(self, temp_store):
        """Test retrieving relevant feedback for a tool."""
        # Record some feedback
        await temp_store.record_feedback(
            tool_name="send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            resolution="Check device reachability first"
        )

        # Retrieve it
        results = await temp_store.get_relevant_feedback(
            tool_name="send_command",
            device_name="R1"
        )

        assert len(results) >= 1
        assert results[0]["tool_name"] == "send_command"
        assert results[0]["resolution"] == "Check device reachability first"

    @pytest.mark.asyncio
    async def test_get_feedback_stats(self, temp_store):
        """Test feedback statistics calculation."""
        # Record multiple feedback entries
        await temp_store.record_feedback(tool_name="health_check", correct=True)
        await temp_store.record_feedback(tool_name="health_check", correct=True)
        await temp_store.record_feedback(
            tool_name="send_command",
            correct=False,
            error_type="syntax"
        )

        stats = await temp_store.get_feedback_stats(days=1)

        assert stats["totals"]["total"] == 3
        assert stats["totals"]["correct_count"] == 2
        assert stats["totals"]["error_count"] == 1

    @pytest.mark.asyncio
    async def test_mark_feedback_learned(self, temp_store):
        """Test marking feedback as learned."""
        import sqlite3

        record_id = await temp_store.record_feedback(
            tool_name="test_tool",
            correct=False,
            resolution="Test fix"
        )

        success = await temp_store.mark_feedback_learned(record_id)
        assert success is True

        # Verify it's marked as learned using direct sqlite connection
        conn = sqlite3.connect(str(temp_store.db_path))
        cursor = conn.execute(
            "SELECT learned FROM feedback WHERE id = ?", (record_id,)
        )
        row = cursor.fetchone()
        conn.close()
        assert row[0] == 1


class TestFeedbackMCPTools:
    """Test the MCP tools for feedback."""

    def test_feedback_tools_registered(self):
        """Verify feedback tools are in the registry."""
        from mcp_tools.feedback import TOOLS

        tool_names = [t["name"] for t in TOOLS]
        assert "feedback_record" in tool_names
        assert "feedback_search" in tool_names
        assert "feedback_stats" in tool_names
        assert "feedback_learn" in tool_names

    def test_feedback_tools_category(self):
        """Verify all feedback tools have correct category."""
        from mcp_tools.feedback import TOOLS

        for tool in TOOLS:
            assert tool["category"] == "memory"

    def test_feedback_tools_callable(self):
        """Verify all feedback tools are callable."""
        from mcp_tools.feedback import TOOLS

        for tool in TOOLS:
            assert callable(tool["fn"])

    def test_feedback_tools_in_global_registry(self):
        """Verify feedback tools are in the global ALL_TOOLS registry."""
        from mcp_tools import ALL_TOOLS

        all_names = [t["name"] for t in ALL_TOOLS]
        assert "feedback_record" in all_names
        assert "feedback_search" in all_names


class TestContextInjectionEnhancement:
    """Test that context injection includes feedback corrections."""

    @pytest.fixture
    def temp_manager(self):
        """Create a MemoryAwareToolManager with temp store."""
        from memory.store import MemoryStore
        from memory.context_manager import MemoryAwareToolManager

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_memory.db"
            chromadb_path = Path(tmpdir) / "test_chromadb"
            store = MemoryStore(db_path=db_path, chromadb_path=chromadb_path)
            manager = MemoryAwareToolManager(memory_store=store)
            yield manager, store

    @pytest.mark.asyncio
    async def test_get_feedback_for_tool(self, temp_manager):
        """Test that get_feedback_for_tool returns feedback records."""
        manager, store = temp_manager

        # Record feedback
        await store.record_feedback(
            tool_name="send_command",
            correct=False,
            device_name="R1",
            error_type="connection",
            resolution="Check reachability first"
        )

        # Retrieve via manager
        feedback = await manager.get_feedback_for_tool(
            tool_name="send_command",
            device_name="R1"
        )

        assert len(feedback) >= 1
        assert feedback[0]["resolution"] == "Check reachability first"

    def test_format_feedback_hint_high_severity(self, temp_manager):
        """Test that high severity feedback gets prefix."""
        manager, _ = temp_manager

        feedback = {
            "tool_name": "send_command",
            "device_name": "R1",
            "error_type": "connection",
            "resolution": "Check connectivity",
            "severity": "high"
        }

        hint = manager._format_feedback_hint(feedback)
        assert hint.startswith("[HIGH]")

    def test_format_feedback_hint_critical_severity(self, temp_manager):
        """Test that critical severity feedback gets prefix."""
        manager, _ = temp_manager

        feedback = {
            "tool_name": "rollback_config",
            "device_name": "R1",
            "error_type": "validation",
            "resolution": "Always use dry_run first",
            "severity": "critical"
        }

        hint = manager._format_feedback_hint(feedback)
        assert hint.startswith("[CRITICAL]")

    def test_format_context_with_feedback(self, temp_manager):
        """Test formatting context that includes feedback."""
        manager, _ = temp_manager

        from memory.models import ContextItem
        from datetime import datetime

        context_items = [
            ContextItem(
                id="1",
                timestamp=datetime.now(),
                item_type="tool_call",
                device="R1",
                content="health_check: status healthy"
            )
        ]

        feedback_items = [
            {
                "tool_name": "send_command",
                "device_name": "R1",
                "error_type": "timeout",
                "resolution": "Increase timeout for slow devices",
                "severity": "medium"
            }
        ]

        result = manager.format_context_for_injection(context_items, feedback_items)

        assert "[Learned Corrections]" in result
        assert "[Memory Context]" in result
        assert "Increase timeout" in result


class TestFeedbackIntegration:
    """Integration tests for the full feedback flow."""

    @pytest.fixture
    def temp_store(self):
        """Create a temporary MemoryStore for testing."""
        from memory.store import MemoryStore

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_memory.db"
            chromadb_path = Path(tmpdir) / "test_chromadb"
            store = MemoryStore(db_path=db_path, chromadb_path=chromadb_path)
            yield store

    @pytest.mark.asyncio
    async def test_full_feedback_workflow(self, temp_store):
        """Test complete workflow: record -> search -> learn."""
        # 1. Record an error
        record_id = await temp_store.record_feedback(
            tool_name="compliance_check",
            correct=False,
            device_name="R1",
            error_type="syntax",
            original_error="Invalid template name",
            resolution="Use compliance_list_templates to see available templates",
            severity="medium"
        )
        assert record_id > 0

        # 2. Search for relevant feedback
        results = await temp_store.get_relevant_feedback(
            tool_name="compliance_check",
            device_name="R1"
        )
        assert len(results) >= 1
        found = [r for r in results if r["id"] == record_id]
        assert len(found) == 1

        # 3. Get stats
        stats = await temp_store.get_feedback_stats(days=1)
        assert stats["totals"]["error_count"] >= 1

        # 4. Mark as learned
        success = await temp_store.mark_feedback_learned(record_id)
        assert success is True

        # 5. Verify learned status using direct sqlite connection
        import sqlite3
        conn = sqlite3.connect(str(temp_store.db_path))
        cursor = conn.execute(
            "SELECT learned FROM feedback WHERE id = ?", (record_id,)
        )
        row = cursor.fetchone()
        conn.close()
        assert row[0] == 1
