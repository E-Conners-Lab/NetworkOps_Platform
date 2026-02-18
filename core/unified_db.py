"""
Unified Database for NetworkOps.

Singleton connection factory that delegates to DatabaseManager.
All tables are managed by Alembic migrations.

Usage:
    from core.unified_db import UnifiedDB

    db = UnifiedDB.get_instance()
    with db.connect() as conn:
        conn.execute("SELECT ...")
"""

import logging
import threading
from pathlib import Path

from core.db import DatabaseManager

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "network_state.db"


class UnifiedDB:
    """
    Unified connection factory — delegates to DatabaseManager.

    Schema is managed by Alembic; _init_schema() is a no-op.
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self, db_path: Path = None):
        # db_path kept for backward compat but ignored
        self._dm = DatabaseManager.get_instance()

    @classmethod
    def get_instance(cls, db_path: Path = None) -> "UnifiedDB":
        """Get or create the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Reset the singleton (for testing)."""
        with cls._lock:
            cls._instance = None
        DatabaseManager.reset()

    def connect(self):
        """Get a connection from the pool (caller must release or use as context manager)."""
        return self._dm.get_connection()

    @property
    def db_path(self) -> Path:
        """Return the database path (for backward compat)."""
        return self._dm.db_path
