"""
Auth database connection - infrastructure only.

This module provides ONLY the database connection.
Schema initialization is in schema.py (to be called by api_server.py at startup).

Uses DatabaseManager singleton for consolidated database access.
"""
import os

from core.db import DatabaseManager, get_connection
from .config import DB_PATH

# In-memory token blacklist fallback when SQLite unavailable
_token_blacklist: set[str] = set()

# Module-level state (set by schema.py after initialization)
USE_SQLITE = False
ENV_USERS: dict = {}

# Database URL for PostgreSQL support (optional)
_AUTH_DB_URL = os.getenv("AUTH_DB_URL") or os.getenv("DATABASE_URL")


def _get_db_connection():
    """Get database connection from the consolidated pool.

    Uses DatabaseManager singleton — same DB as all other modules.
    """
    return DatabaseManager.get_instance().get_connection()
