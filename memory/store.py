"""
MemoryStore - Persistent storage for MCP Memory System.

Combines SQLite for structured queries with ChromaDB for semantic search.
Uses aiosqlite for true async database operations.
"""

import sqlite3
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from contextlib import contextmanager, asynccontextmanager

import aiosqlite

# Configure module logger
logger = logging.getLogger(__name__)

from .models import ContextItem
from .config import get_config


class MemoryStore:
    """
    Persistent memory storage with SQLite and optional ChromaDB.

    Provides:
    - Tool call history recording
    - Device state snapshots
    - Conversation summaries
    - Context retrieval for injection
    """

    # Tools that benefit from richer context
    INVESTIGATIVE_TOOLS = {
        "health_check", "health_check_all", "full_network_test",
        "get_interface_status", "pyats_diff_state", "discover_topology",
        "get_bgp_neighbors_netconf", "send_command"
    }

    # Tool similarity for relevance scoring
    TOOL_SIMILARITY = {
        ("health_check", "health_check_all"): 0.9,
        ("health_check", "full_network_test"): 0.8,
        ("send_config", "remediate_interface"): 0.7,
        ("get_interface_status", "remediate_interface"): 0.9,
        ("pyats_snapshot_state", "pyats_diff_state"): 0.9,
    }

    def __init__(
        self,
        db_path: Optional[Path] = None,
        chromadb_path: Optional[Path] = None,
        enable_semantic: bool = True
    ):
        """
        Initialize memory store.

        Args:
            db_path: Path to SQLite database file
            chromadb_path: Path to ChromaDB persistence directory
            enable_semantic: Whether to enable semantic search (requires chromadb)
        """
        self.db_path = db_path or Path(__file__).parent.parent / "data" / "networkops.db"
        self.chromadb_path = chromadb_path or Path(__file__).parent.parent / "data" / "chromadb"
        self.enable_semantic = enable_semantic

        # Ensure directories exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize SQLite
        self._init_db()

        # Initialize ChromaDB (lazy load)
        self._chroma_client = None
        self._collection = None
        self._embedding_service = None

        # Track if async init has been run
        self._initialized = False

    async def initialize(self):
        """
        Async initialization - runs maintenance if configured.

        Call this after construction to enable auto-pruning on startup.
        Safe to call multiple times (idempotent).
        """
        if self._initialized:
            return

        config = get_config()

        if config.auto_prune_on_startup:
            logger.info("Running startup maintenance...")
            try:
                results = await self.run_maintenance()
                total = (
                    sum(results["prune_by_age"].values()) +
                    sum(results["prune_by_count"].values())
                )
                if total > 0:
                    logger.info(f"Startup maintenance pruned {total} records")
            except Exception as e:
                logger.warning(f"Startup maintenance failed: {e}")

        self._initialized = True

    def _init_db(self):
        """Initialize SQLite database schema with production settings."""
        with self._get_connection() as conn:
            # Enable WAL mode for better concurrent read/write performance
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")

            # Run integrity check on existing database
            result = conn.execute("PRAGMA integrity_check").fetchone()
            if result[0] != "ok":
                logger.warning(f"Database integrity check failed: {result[0]}")
            else:
                logger.debug("Database integrity check passed")

            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    device_name TEXT,
                    arguments TEXT,
                    result_summary TEXT,
                    duration_ms INTEGER,
                    status TEXT DEFAULT 'success'
                );

                CREATE INDEX IF NOT EXISTS idx_tool_calls_device
                    ON tool_calls(device_name);
                CREATE INDEX IF NOT EXISTS idx_tool_calls_tool
                    ON tool_calls(tool_name);
                CREATE INDEX IF NOT EXISTS idx_tool_calls_ts
                    ON tool_calls(timestamp);

                CREATE TABLE IF NOT EXISTS device_states (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    state_type TEXT,
                    data TEXT,
                    label TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_device_states_device
                    ON device_states(device_name);
                CREATE INDEX IF NOT EXISTS idx_device_states_type
                    ON device_states(state_type);

                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_id TEXT,
                    summary TEXT,
                    tools_used TEXT,
                    devices_mentioned TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_conversations_ts
                    ON conversations(timestamp);

                -- Feedback table for error learning
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool_call_id INTEGER,
                    session_id TEXT,
                    tool_name TEXT NOT NULL,
                    device_name TEXT,
                    correct BOOLEAN NOT NULL,
                    error_type TEXT,
                    original_error TEXT,
                    correction TEXT,
                    resolution TEXT,
                    severity TEXT DEFAULT 'medium',
                    learned BOOLEAN DEFAULT 0,
                    FOREIGN KEY (tool_call_id) REFERENCES tool_calls(id)
                );

                CREATE INDEX IF NOT EXISTS idx_feedback_tool
                    ON feedback(tool_name);
                CREATE INDEX IF NOT EXISTS idx_feedback_device
                    ON feedback(device_name);
                CREATE INDEX IF NOT EXISTS idx_feedback_error_type
                    ON feedback(error_type);
                CREATE INDEX IF NOT EXISTS idx_feedback_learned
                    ON feedback(learned);
            """)

    @contextmanager
    def _get_connection(self):
        """Get a sync database connection (used for initialization only)."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @asynccontextmanager
    async def _get_async_connection(self):
        """Get an async database connection with proper cleanup."""
        conn = await aiosqlite.connect(str(self.db_path))
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
            await conn.commit()
        finally:
            await conn.close()

    async def _get_chroma_collection(self):
        """Lazy-load ChromaDB collection."""
        if self._collection is None and self.enable_semantic:
            try:
                import chromadb
                from .embeddings import EmbeddingService

                self.chromadb_path.mkdir(parents=True, exist_ok=True)
                self._chroma_client = chromadb.PersistentClient(
                    path=str(self.chromadb_path)
                )
                self._collection = self._chroma_client.get_or_create_collection(
                    name="network_memory",
                    metadata={"description": "Network automation memory"}
                )
                self._embedding_service = EmbeddingService()
            except ImportError:
                self.enable_semantic = False
                return None
        return self._collection

    # ===== Recording Methods =====

    async def record_tool_call(
        self,
        tool_name: str,
        device_name: Optional[str] = None,
        arguments: Optional[dict] = None,
        result_summary: Optional[str] = None,
        duration_ms: Optional[int] = None,
        status: str = "success"
    ) -> int:
        """
        Record a tool invocation.

        Returns the record ID.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO tool_calls
                (timestamp, tool_name, device_name, arguments, result_summary, duration_ms, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    tool_name,
                    device_name,
                    json.dumps(arguments or {}),
                    result_summary,
                    duration_ms,
                    status
                )
            )
            record_id = cursor.lastrowid

        # Also index in ChromaDB for semantic search
        if self.enable_semantic and result_summary:
            await self._index_for_semantic(
                doc_id=f"tool_{record_id}",
                content=f"{tool_name} on {device_name or 'network'}: {result_summary}",
                metadata={
                    "type": "tool_call",
                    "tool_name": tool_name,
                    "device": device_name,
                    "timestamp": timestamp
                }
            )

        return record_id

    async def record_device_state(
        self,
        device_name: str,
        state_type: str,
        data: dict,
        label: Optional[str] = None
    ) -> int:
        """Record a device state snapshot."""
        timestamp = datetime.now(timezone.utc).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO device_states
                (timestamp, device_name, state_type, data, label)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, device_name, state_type, json.dumps(data), label)
            )
            return cursor.lastrowid

    async def record_conversation(
        self,
        summary: str,
        tools_used: Optional[list[str]] = None,
        devices_mentioned: Optional[list[str]] = None,
        session_id: Optional[str] = None
    ) -> int:
        """Record a conversation summary."""
        timestamp = datetime.now(timezone.utc).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO conversations
                (timestamp, session_id, summary, tools_used, devices_mentioned)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    session_id,
                    summary,
                    json.dumps(tools_used or []),
                    json.dumps(devices_mentioned or [])
                )
            )
            record_id = cursor.lastrowid

        # Index for semantic search
        if self.enable_semantic:
            await self._index_for_semantic(
                doc_id=f"conv_{record_id}",
                content=summary,
                metadata={
                    "type": "conversation",
                    "devices": ",".join(devices_mentioned) if devices_mentioned else "",
                    "timestamp": timestamp
                }
            )

        return record_id

    async def save_note(
        self,
        note: str,
        devices: Optional[list[str]] = None,
        topics: Optional[list[str]] = None
    ) -> int:
        """Save an explicit note to memory."""
        return await self.record_conversation(
            summary=note,
            devices_mentioned=devices,
            tools_used=topics  # Reusing field for topics
        )

    # ===== Feedback Methods (Error Learning) =====

    async def record_feedback(
        self,
        tool_name: str,
        correct: bool,
        device_name: Optional[str] = None,
        tool_call_id: Optional[int] = None,
        session_id: Optional[str] = None,
        error_type: Optional[str] = None,
        original_error: Optional[str] = None,
        correction: Optional[str] = None,
        resolution: Optional[str] = None,
        severity: str = "medium"
    ) -> int:
        """
        Record feedback on a tool execution for error learning.

        Args:
            tool_name: Name of the tool
            correct: Whether the action was correct
            device_name: Device involved (if any)
            tool_call_id: Links to specific tool_calls record
            session_id: Session identifier
            error_type: Categorized error (connection, syntax, logic, timeout, etc.)
            original_error: What went wrong
            correction: What should have happened
            resolution: How it was eventually fixed
            severity: low/medium/high/critical

        Returns:
            Record ID
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO feedback
                (timestamp, tool_call_id, session_id, tool_name, device_name,
                 correct, error_type, original_error, correction, resolution, severity, learned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    timestamp, tool_call_id, session_id, tool_name, device_name,
                    correct, error_type, original_error, correction, resolution, severity
                )
            )
            record_id = cursor.lastrowid

        # Index for semantic search if there's a resolution
        if self.enable_semantic and (resolution or correction):
            content = f"Error learning: {tool_name}"
            if device_name:
                content += f" on {device_name}"
            if error_type:
                content += f" - {error_type}"
            if resolution:
                content += f". Fix: {resolution}"
            elif correction:
                content += f". Should: {correction}"

            await self._index_for_semantic(
                doc_id=f"feedback_{record_id}",
                content=content,
                metadata={
                    "type": "feedback",
                    "tool_name": tool_name,
                    "device": device_name,
                    "error_type": error_type,
                    "correct": correct,
                    "timestamp": timestamp
                }
            )

        logger.info(f"Recorded feedback for {tool_name}: correct={correct}, error_type={error_type}")
        return record_id

    async def get_relevant_feedback(
        self,
        tool_name: str,
        device_name: Optional[str] = None,
        error_type: Optional[str] = None,
        limit: int = 5
    ) -> list[dict]:
        """
        Get relevant feedback/corrections for a tool.

        Prioritizes:
        1. Same tool + same device + same error type
        2. Same tool + same device
        3. Same tool + same error type
        4. Same tool
        """
        async with self._get_async_connection() as conn:
            # Build query with relevance scoring
            query = """
                SELECT
                    id, timestamp, tool_name, device_name, correct,
                    error_type, original_error, correction, resolution, severity,
                    CASE
                        WHEN tool_name = ? AND device_name = ? AND error_type = ? THEN 4
                        WHEN tool_name = ? AND device_name = ? THEN 3
                        WHEN tool_name = ? AND error_type = ? THEN 2
                        WHEN tool_name = ? THEN 1
                        ELSE 0
                    END as relevance
                FROM feedback
                WHERE tool_name = ? AND correct = 0
                ORDER BY relevance DESC, timestamp DESC
                LIMIT ?
            """
            params = (
                tool_name, device_name, error_type,  # Case 4
                tool_name, device_name,               # Case 3
                tool_name, error_type,                # Case 2
                tool_name,                            # Case 1
                tool_name,                            # WHERE
                limit
            )

            cursor = await conn.execute(query, params)
            rows = [dict(row) async for row in cursor]

        return rows

    async def get_feedback_stats(
        self,
        days: int = 30
    ) -> dict:
        """Get feedback statistics for analysis."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        async with self._get_async_connection() as conn:
            # Total counts
            cursor = await conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN correct = 1 THEN 1 ELSE 0 END) as correct_count,
                    SUM(CASE WHEN correct = 0 THEN 1 ELSE 0 END) as error_count
                FROM feedback
                WHERE timestamp > ?
                """,
                (cutoff,)
            )
            totals = dict(await cursor.fetchone())

            # By tool
            cursor = await conn.execute(
                """
                SELECT tool_name,
                    COUNT(*) as total,
                    SUM(CASE WHEN correct = 0 THEN 1 ELSE 0 END) as errors
                FROM feedback
                WHERE timestamp > ?
                GROUP BY tool_name
                ORDER BY errors DESC
                LIMIT 10
                """,
                (cutoff,)
            )
            by_tool = [dict(row) async for row in cursor]

            # By error type
            cursor = await conn.execute(
                """
                SELECT error_type, COUNT(*) as count
                FROM feedback
                WHERE timestamp > ? AND error_type IS NOT NULL
                GROUP BY error_type
                ORDER BY count DESC
                """,
                (cutoff,)
            )
            by_error_type = [dict(row) async for row in cursor]

            # Unlearned corrections (not yet incorporated)
            cursor = await conn.execute(
                """
                SELECT COUNT(*) as unlearned
                FROM feedback
                WHERE correct = 0 AND learned = 0 AND resolution IS NOT NULL
                """
            )
            unlearned = (await cursor.fetchone())[0]

        return {
            "period_days": days,
            "totals": totals,
            "by_tool": by_tool,
            "by_error_type": by_error_type,
            "unlearned_corrections": unlearned
        }

    async def mark_feedback_learned(self, feedback_id: int) -> bool:
        """Mark a feedback record as learned/incorporated."""
        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                "UPDATE feedback SET learned = 1 WHERE id = ?",
                (feedback_id,)
            )
            return cursor.rowcount > 0

    # ===== Retrieval Methods =====

    async def get_device_events(
        self,
        device_name: str,
        limit: int = 10,
        time_window_minutes: int = 60
    ) -> list[ContextItem]:
        """Get recent events for a specific device."""
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT id, timestamp, tool_name, arguments, result_summary, status
                FROM tool_calls
                WHERE device_name = ? AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (device_name, cutoff, limit)
            )
            rows = [dict(row) async for row in cursor]

        return [
            ContextItem(
                id=f"tool_{row['id']}",
                timestamp=datetime.fromisoformat(row['timestamp']),
                item_type="tool_call",
                device=device_name,
                content=row['result_summary'] or f"{row['tool_name']} executed",
                metadata={"tool_name": row['tool_name'], "status": row['status']}
            )
            for row in rows
            if row['result_summary']
        ]

    async def get_tool_history(
        self,
        tool_name: str,
        device_name: Optional[str] = None,
        limit: int = 5
    ) -> list[ContextItem]:
        """Get recent history for a specific tool."""
        async with self._get_async_connection() as conn:
            if device_name:
                cursor = await conn.execute(
                    """
                    SELECT id, timestamp, device_name, result_summary, status
                    FROM tool_calls
                    WHERE tool_name = ? AND device_name = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (tool_name, device_name, limit)
                )
            else:
                cursor = await conn.execute(
                    """
                    SELECT id, timestamp, device_name, result_summary, status
                    FROM tool_calls
                    WHERE tool_name = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (tool_name, limit)
                )
            rows = [dict(row) async for row in cursor]

        return [
            ContextItem(
                id=f"tool_{row['id']}",
                timestamp=datetime.fromisoformat(row['timestamp']),
                item_type="tool_call",
                device=row['device_name'],
                content=row['result_summary'] or f"{tool_name} executed",
                metadata={"tool_name": tool_name, "status": row['status']}
            )
            for row in rows
            if row['result_summary']
        ]

    async def get_recent_context(
        self,
        limit: int = 10,
        time_window_minutes: int = 60
    ) -> list[ContextItem]:
        """Get recent context across all devices."""
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)).isoformat()

        async with self._get_async_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT id, timestamp, tool_name, device_name, result_summary, status
                FROM tool_calls
                WHERE timestamp > ? AND result_summary IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (cutoff, limit)
            )
            rows = [dict(row) async for row in cursor]

        return [
            ContextItem(
                id=f"tool_{row['id']}",
                timestamp=datetime.fromisoformat(row['timestamp']),
                item_type="tool_call",
                device=row['device_name'],
                content=row['result_summary'],
                metadata={"tool_name": row['tool_name'], "status": row['status']}
            )
            for row in rows
        ]

    async def semantic_search(
        self,
        query: str,
        limit: int = 5
    ) -> list[ContextItem]:
        """Search memory using semantic similarity."""
        collection = await self._get_chroma_collection()
        if not collection or not self._embedding_service:
            return []

        try:
            # Get embedding for query
            query_embedding = await self._embedding_service.embed(query)

            # Search ChromaDB
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=limit
            )

            items = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i] if results['metadatas'] else {}
                    distance = results['distances'][0][i] if results['distances'] else 1.0

                    items.append(ContextItem(
                        id=results['ids'][0][i],
                        timestamp=datetime.fromisoformat(
                            metadata.get('timestamp', datetime.now(timezone.utc).isoformat())
                        ),
                        item_type=metadata.get('type', 'unknown'),
                        device=metadata.get('device'),
                        content=doc,
                        metadata=metadata,
                        semantic_score=1.0 - distance  # Convert distance to similarity
                    ))

            return items

        except Exception as e:
            logger.error(f"Semantic search error: {e}")
            return []

    async def get_relevant_context(
        self,
        tool_name: str,
        device_name: Optional[str] = None,
        limit: int = 5,
        time_window_minutes: int = 60
    ) -> list[ContextItem]:
        """
        Get relevant context for a tool call.

        Combines:
        - Recent device events (if device specified)
        - Tool history
        - Semantic search (for investigative tools)
        """
        context_items = []

        # 1. Recent events for this device
        if device_name:
            device_events = await self.get_device_events(
                device_name, limit=3, time_window_minutes=time_window_minutes
            )
            context_items.extend(device_events)

        # 2. Tool-specific history
        tool_history = await self.get_tool_history(
            tool_name, device_name, limit=2
        )
        context_items.extend(tool_history)

        # 3. Semantic search for investigative tools
        if tool_name in self.INVESTIGATIVE_TOOLS and self.enable_semantic:
            query = f"{tool_name} {device_name or 'network'}"
            semantic_hits = await self.semantic_search(query, limit=2)
            context_items.extend(semantic_hits)

        # Score and rank
        scored = self._score_context(context_items, tool_name, device_name)

        # Deduplicate by ID
        seen = set()
        unique = []
        for item in scored:
            if item.id not in seen:
                seen.add(item.id)
                unique.append(item)

        return unique[:limit]

    def _score_context(
        self,
        items: list[ContextItem],
        current_tool: str,
        current_device: Optional[str]
    ) -> list[ContextItem]:
        """Score and rank context items by relevance."""
        import math
        now = datetime.now(timezone.utc)

        for item in items:
            score = 0.0

            # Time decay (half-life = 1 hour)
            age_hours = (now - item.timestamp).total_seconds() / 3600
            time_score = math.exp(-0.693 * age_hours)
            score += time_score * 0.3

            # Device match
            if current_device and item.device == current_device:
                score += 0.4

            # Tool similarity
            item_tool = item.metadata.get('tool_name', '')
            similarity_key = (current_tool, item_tool)
            reverse_key = (item_tool, current_tool)
            tool_sim = self.TOOL_SIMILARITY.get(
                similarity_key,
                self.TOOL_SIMILARITY.get(reverse_key, 0.0)
            )
            score += tool_sim * 0.2

            # Semantic score
            if item.semantic_score:
                score += item.semantic_score * 0.1

            item.relevance_score = score

        return sorted(items, key=lambda x: x.relevance_score, reverse=True)

    async def _index_for_semantic(
        self,
        doc_id: str,
        content: str,
        metadata: dict
    ):
        """Index content for semantic search."""
        collection = await self._get_chroma_collection()
        if not collection or not self._embedding_service:
            return

        try:
            embedding = await self._embedding_service.embed(content)
            collection.upsert(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[content],
                metadatas=[metadata]
            )
        except Exception as e:
            logger.error(f"Semantic indexing error: {e}")

    # ===== Statistics =====

    async def get_stats(self) -> dict:
        """Get comprehensive memory store statistics."""
        async with self._get_async_connection() as conn:
            # Record counts
            tool_count = await conn.execute_fetchall("SELECT COUNT(*) FROM tool_calls")
            device_count = await conn.execute_fetchall("SELECT COUNT(*) FROM device_states")
            conv_count = await conn.execute_fetchall("SELECT COUNT(*) FROM conversations")

            # Date range for tool_calls
            date_range = await conn.execute_fetchall(
                "SELECT MIN(timestamp), MAX(timestamp) FROM tool_calls"
            )

            stats = {
                "tool_calls": tool_count[0][0],
                "device_states": device_count[0][0],
                "conversations": conv_count[0][0],
            }

            # Add date range if records exist
            if date_range[0][0]:
                stats["oldest_record"] = date_range[0][0]
                stats["newest_record"] = date_range[0][1]

        # Database file size
        if self.db_path.exists():
            stats["database_size_bytes"] = self.db_path.stat().st_size

        # ChromaDB stats if available
        collection = await self._get_chroma_collection()
        if collection:
            stats["semantic_documents"] = collection.count()

        # Health status
        stats["is_healthy"] = self.is_healthy()

        return stats

    # ===== Maintenance & Retention =====

    async def prune_old_records(self, days: int = None) -> dict:
        """
        Delete records older than the specified number of days.

        Args:
            days: Number of days to retain. Uses config default if not specified.

        Returns:
            Dict with counts of deleted records per table.
        """
        if days is None:
            days = get_config().retention_days

        if days <= 0:
            logger.debug("Retention pruning disabled (days=0)")
            return {"tool_calls": 0, "device_states": 0, "conversations": 0}

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        async with self._get_async_connection() as conn:
            # Delete old tool calls
            cursor = await conn.execute(
                "DELETE FROM tool_calls WHERE timestamp < ?", (cutoff,)
            )
            tool_count = cursor.rowcount

            # Delete old device states
            cursor = await conn.execute(
                "DELETE FROM device_states WHERE timestamp < ?", (cutoff,)
            )
            device_count = cursor.rowcount

            # Delete old conversations
            cursor = await conn.execute(
                "DELETE FROM conversations WHERE timestamp < ?", (cutoff,)
            )
            conv_count = cursor.rowcount

            result = {
                "tool_calls": tool_count,
                "device_states": device_count,
                "conversations": conv_count
            }

        total = sum(result.values())
        if total > 0:
            logger.info(f"Pruned {total} old records (older than {days} days)")

        return result

    async def prune_by_count(
        self,
        max_tool_calls: int = None,
        max_conversations: int = None,
        max_device_states: int = None
    ) -> dict:
        """
        Prune tables to keep only the N most recent records.

        Args:
            max_tool_calls: Maximum tool_calls to keep
            max_conversations: Maximum conversations to keep
            max_device_states: Maximum device_states to keep

        Returns:
            Dict with counts of deleted records per table.
        """
        config = get_config()
        max_tool_calls = max_tool_calls or config.max_tool_calls
        max_conversations = max_conversations or config.max_conversations
        max_device_states = max_device_states or config.max_device_states

        async with self._get_async_connection() as conn:
            # Prune tool_calls
            cursor = await conn.execute(
                """
                DELETE FROM tool_calls WHERE id NOT IN (
                    SELECT id FROM tool_calls ORDER BY timestamp DESC LIMIT ?
                )
                """,
                (max_tool_calls,)
            )
            tool_count = cursor.rowcount

            # Prune conversations
            cursor = await conn.execute(
                """
                DELETE FROM conversations WHERE id NOT IN (
                    SELECT id FROM conversations ORDER BY timestamp DESC LIMIT ?
                )
                """,
                (max_conversations,)
            )
            conv_count = cursor.rowcount

            # Prune device_states
            cursor = await conn.execute(
                """
                DELETE FROM device_states WHERE id NOT IN (
                    SELECT id FROM device_states ORDER BY timestamp DESC LIMIT ?
                )
                """,
                (max_device_states,)
            )
            device_count = cursor.rowcount

            result = {
                "tool_calls": tool_count,
                "conversations": conv_count,
                "device_states": device_count
            }

        total = sum(result.values())
        if total > 0:
            logger.info(f"Pruned {total} records by count limits")

        return result

    async def vacuum(self) -> int:
        """
        Reclaim disk space after deletions.

        Returns:
            Size reduction in bytes (approximate).
        """
        # Get size before
        size_before = self.db_path.stat().st_size if self.db_path.exists() else 0

        async with self._get_async_connection() as conn:
            await conn.execute("VACUUM")

        # Get size after
        size_after = self.db_path.stat().st_size if self.db_path.exists() else 0
        reduction = size_before - size_after
        if reduction > 0:
            logger.info(f"Vacuum reclaimed {reduction} bytes")

        return reduction

    async def run_maintenance(self) -> dict:
        """
        Run all maintenance tasks: prune by age, prune by count, vacuum.

        Returns:
            Summary of maintenance operations.
        """
        results = {
            "prune_by_age": await self.prune_old_records(),
            "prune_by_count": await self.prune_by_count(),
            "vacuum_bytes": await self.vacuum()
        }

        logger.info(f"Maintenance complete: {results}")
        return results

    # ===== Backup & Recovery =====

    async def backup(self, backup_path: Path = None) -> Path:
        """
        Create a backup of the SQLite database.

        Args:
            backup_path: Destination path. Auto-generated if not specified.

        Returns:
            Path to the backup file.
        """
        config = get_config()

        if backup_path is None:
            config.backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = config.backup_dir / f"memory_{timestamp}.db"

        def _backup():
            # Use SQLite's backup API for consistency
            with self._get_connection() as conn:
                backup_conn = sqlite3.connect(str(backup_path))
                conn.backup(backup_conn)
                backup_conn.close()

        await asyncio.to_thread(_backup)
        logger.info(f"Created backup: {backup_path}")

        # Cleanup old backups
        await self._cleanup_old_backups()

        return backup_path

    async def _cleanup_old_backups(self):
        """Remove old backup files, keeping only the most recent."""
        config = get_config()

        if not config.backup_dir.exists():
            return

        backups = sorted(
            config.backup_dir.glob("memory_*.db"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        for old_backup in backups[config.max_backups:]:
            old_backup.unlink()
            logger.debug(f"Removed old backup: {old_backup}")

    async def check_integrity(self) -> tuple[bool, str]:
        """
        Run SQLite integrity check.

        Returns:
            Tuple of (is_ok, message).
        """
        async with self._get_async_connection() as conn:
            rows = await conn.execute_fetchall("PRAGMA integrity_check")
            result = rows[0][0]

        is_ok = result == "ok"

        if not is_ok:
            logger.warning(f"Integrity check failed: {result}")

        return is_ok, result

    async def repair(self) -> dict:
        """
        Attempt to repair the database.

        Runs integrity check, rebuilds indexes, and vacuums.

        Returns:
            Summary of repair operations.
        """
        results = {}

        # Check integrity
        is_ok, message = await self.check_integrity()
        results["integrity_before"] = message

        async with self._get_async_connection() as conn:
            # Reindex all tables
            await conn.execute("REINDEX")

        results["reindex"] = True

        # Vacuum
        results["vacuum_bytes"] = await self.vacuum()

        # Check again
        is_ok, message = await self.check_integrity()
        results["integrity_after"] = message
        results["success"] = is_ok

        logger.info(f"Repair complete: {results}")
        return results

    def is_healthy(self) -> bool:
        """
        Quick health check for the memory store.

        Returns:
            True if the database is accessible and passes basic checks.
        """
        try:
            with self._get_connection() as conn:
                conn.execute("SELECT 1").fetchone()
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
