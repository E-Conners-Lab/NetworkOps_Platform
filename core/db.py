"""
Database abstraction layer (DB-API 2.0 connection factory).

Provides a thin abstraction over sqlite3 and psycopg2 for database portability.
NOT an ORM — just connection management and SQL dialect adaptation.

Usage:
    from core.db import connect, get_connection, adapt_schema_sql

    # Context manager (auto commit/rollback/close)
    with connect() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (1,))
        row = cursor.fetchone()

    # Raw connection
    conn = get_connection()
    try:
        ...
    finally:
        conn.close()

    # SQL adaptation for PostgreSQL
    sql = adapt_schema_sql("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)")
    # -> "CREATE TABLE t (id SERIAL PRIMARY KEY)" when using PostgreSQL
"""

import logging
import os
import queue
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def is_postgres(db_url: Optional[str] = None) -> bool:
    """Check if the given URL points to PostgreSQL."""
    if db_url is None:
        return False
    return db_url.startswith("postgresql://") or db_url.startswith("postgres://")


def get_connection(
    db_url: Optional[str] = None,
    db_path: Optional[str] = None,
) -> sqlite3.Connection:
    """
    Get a DB-API 2.0 connection.

    Args:
        db_url: Database URL (postgresql:// or sqlite:// or None)
        db_path: SQLite file path (used when db_url is None or sqlite)

    Returns:
        DB-API 2.0 connection with row_factory set for dict-like access.
    """
    if db_url and is_postgres(db_url):
        return _get_postgres_connection(db_url)

    # Default to SQLite
    path = db_path or ":memory:"
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _get_postgres_connection(db_url: str):
    """Get a PostgreSQL connection via psycopg2."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        raise ImportError(
            "psycopg2 is required for PostgreSQL connections. "
            "Install with: pip install psycopg2-binary"
        )

    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    # Use RealDictCursor for dict-like row access
    return _CompatConnection(conn)


class _CompatConnection:
    """
    Wraps a psycopg2 connection to provide SQLite-compatible interface.

    - Accepts '?' placeholders and converts to '%s'
    - Returns dict-like rows via RealDictCursor
    - Proxies commit/rollback/close
    """

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        import psycopg2.extras
        return _CompatCursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def execute(self, sql, params=None):
        return self.cursor().execute(sql, params)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _CompatCursor:
    """Wraps a psycopg2 cursor to accept '?' placeholders.

    Also injects RETURNING id for INSERT statements so lastrowid works
    on PostgreSQL (psycopg2 cursors don't natively support lastrowid).
    """

    def __init__(self, cursor):
        self._cursor = cursor
        self._last_id = None

    def execute(self, sql, params=None):
        # Convert ? to %s for psycopg2
        adapted_sql = sql.replace("?", "%s")

        # For INSERT statements, append RETURNING id so we can populate lastrowid
        upper = adapted_sql.strip().upper()
        if upper.startswith("INSERT") and "RETURNING" not in upper:
            adapted_sql = adapted_sql.rstrip().rstrip(";") + " RETURNING id"
            self._cursor.execute(adapted_sql, params)
            row = self._cursor.fetchone()
            if row:
                self._last_id = row[0] if isinstance(row, tuple) else row.get("id")
            return
        else:
            self._last_id = None

        return self._cursor.execute(adapted_sql, params)

    def executemany(self, sql, params_seq):
        adapted_sql = sql.replace("?", "%s")
        return self._cursor.executemany(adapted_sql, params_seq)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size=None):
        if size is not None:
            return self._cursor.fetchmany(size)
        return self._cursor.fetchmany()

    @property
    def lastrowid(self):
        if self._last_id is not None:
            return self._last_id
        return self._cursor.lastrowid if hasattr(self._cursor, 'lastrowid') else None

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        self._cursor.close()


@contextmanager
def connect(
    db_url: Optional[str] = None,
    db_path: Optional[str] = None,
):
    """
    Context manager that yields a connection with auto commit/rollback.

    On success: commits and closes.
    On exception: rolls back and closes.

    Usage:
        with connect(db_path="/data/users.db") as conn:
            conn.cursor().execute("INSERT INTO ...")
    """
    conn = get_connection(db_url=db_url, db_path=db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def adapt_schema_sql(sql: str, db_url: Optional[str] = None) -> str:
    """
    Adapt SQLite schema SQL for the target database dialect.

    Conversions for PostgreSQL:
    - INTEGER PRIMARY KEY AUTOINCREMENT -> SERIAL PRIMARY KEY
    - No other changes needed (TEXT, INTEGER work in both)

    Args:
        sql: SQLite-flavored SQL string
        db_url: Target database URL (None = SQLite, no changes)

    Returns:
        Adapted SQL string
    """
    if not is_postgres(db_url):
        return sql

    # AUTOINCREMENT -> SERIAL
    adapted = re.sub(
        r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT',
        'SERIAL PRIMARY KEY',
        sql,
        flags=re.IGNORECASE,
    )

    return adapted


_IDENTIFIER_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


def _validate_identifier(name: str, label: str) -> None:
    """Validate a SQL identifier (table or column name) against injection.

    Raises ValueError if the identifier contains invalid characters.
    """
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid {label} name: {name!r}")


def column_exists(conn, table: str, column: str, db_url: Optional[str] = None) -> bool:
    """
    Check if a column exists in a table (dialect-aware).

    Args:
        conn: Database connection
        table: Table name
        column: Column name
        db_url: Database URL for dialect detection

    Returns:
        True if column exists

    Raises:
        ValueError: If table or column names contain invalid characters
    """
    _validate_identifier(table, "table")
    _validate_identifier(column, "column")

    if is_postgres(db_url):
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = ? AND column_name = ?",
            (table, column),
        )
        return cursor.fetchone() is not None
    else:
        # SQLite: use PRAGMA table_info instead of f-string SQL
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row[1] if isinstance(row, tuple) else row["name"] for row in cursor.fetchall()]
        return column in columns


# =============================================================================
# DatabaseManager — consolidated connection pool singleton
# =============================================================================

_DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "networkops.db"


class DatabaseManager:
    """
    Singleton connection pool for the consolidated database.

    Reads DATABASE_URL env var for PostgreSQL; defaults to
    data/networkops.db (SQLite) when unset.

    Usage:
        dm = DatabaseManager.get_instance()
        with dm.connect() as conn:
            conn.execute("SELECT ...")
    """

    _instance: Optional["DatabaseManager"] = None
    _lock = threading.Lock()

    def __init__(
        self,
        db_url: Optional[str] = None,
        db_path: Optional[Path] = None,
        pool_size: int = 10,
    ):
        self._db_url = db_url or os.environ.get("DATABASE_URL")
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._pool_size = pool_size
        self._use_postgres = is_postgres(self._db_url)

        # Ensure data directory exists for SQLite
        if not self._use_postgres:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Connection pool (SQLite only — PostgreSQL uses psycopg2 pool)
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)
        self._pg_pool = None

        if self._use_postgres:
            self._init_pg_pool()

    def _init_pg_pool(self):
        """Initialize PostgreSQL connection pool."""
        try:
            import psycopg2.pool
        except ImportError:
            raise ImportError(
                "psycopg2 is required for PostgreSQL. "
                "Install with: pip install psycopg2-binary"
            )
        self._pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=self._pool_size,
            dsn=self._db_url,
        )

    @classmethod
    def get_instance(
        cls,
        db_url: Optional[str] = None,
        db_path: Optional[Path] = None,
    ) -> "DatabaseManager":
        """Get or create the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(db_url=db_url, db_path=db_path)
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset the singleton and drain the pool. For testing only."""
        with cls._lock:
            if cls._instance is not None:
                inst = cls._instance
                # Drain SQLite pool
                while not inst._pool.empty():
                    try:
                        conn = inst._pool.get_nowait()
                        conn.close()
                    except (queue.Empty, Exception):
                        pass
                # Close PostgreSQL pool
                if inst._pg_pool is not None:
                    try:
                        inst._pg_pool.closeall()
                    except Exception:
                        pass
                cls._instance = None

    # ----- connection acquisition / release -----------------------------------

    def get_connection(self):
        """Acquire a connection from the pool."""
        if self._use_postgres:
            raw = self._pg_pool.getconn()
            raw.autocommit = False
            return _CompatConnection(raw)

        # SQLite — try pool first, create new if empty
        try:
            conn = self._pool.get_nowait()
            # Verify connection is still usable
            conn.execute("SELECT 1")
            return conn
        except queue.Empty:
            pass
        except Exception:
            pass  # Stale connection — create a new one

        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def release_connection(self, conn):
        """Return a connection to the pool."""
        if self._use_postgres:
            # Unwrap _CompatConnection
            raw = conn._conn if isinstance(conn, _CompatConnection) else conn
            try:
                self._pg_pool.putconn(raw)
            except Exception:
                pass
            return

        # SQLite — return to pool if there's room
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            conn.close()

    @contextmanager
    def connect(self):
        """Context manager: acquire → yield → commit/rollback → release."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.release_connection(conn)

    @property
    def db_path(self) -> Path:
        """Return the SQLite database path."""
        return self._db_path

    @property
    def db_url(self) -> Optional[str]:
        """Return the database URL (None for SQLite)."""
        return self._db_url
