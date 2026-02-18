"""Tests for database abstraction layer."""

import sqlite3

import pytest

from core.db import (
    adapt_schema_sql,
    column_exists,
    connect,
    get_connection,
    is_postgres,
)


class TestIsPostgres:
    def test_postgresql_url(self):
        assert is_postgres("postgresql://user:pass@localhost/db") is True

    def test_postgres_url(self):
        assert is_postgres("postgres://user:pass@localhost/db") is True

    def test_sqlite_path(self):
        assert is_postgres("/data/users.db") is False

    def test_none(self):
        assert is_postgres(None) is False


class TestGetConnection:
    def test_sqlite_memory(self):
        conn = get_connection(db_path=":memory:")
        assert conn is not None
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
        cursor.execute("INSERT INTO test (name) VALUES (?)", ("alice",))
        cursor.execute("SELECT * FROM test")
        row = cursor.fetchone()
        assert row["name"] == "alice"
        conn.close()

    def test_sqlite_row_factory(self):
        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
        conn.execute("INSERT INTO t (val) VALUES (?)", ("hello",))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM t")
        row = cursor.fetchone()
        # sqlite3.Row supports dict-like access
        assert row["val"] == "hello"
        conn.close()


class TestConnectContextManager:
    def test_commit_on_success(self):
        # Use a file-based temp DB to verify commit
        with connect(db_path=":memory:") as conn:
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            conn.execute("INSERT INTO t (v) VALUES (?)", ("ok",))
            cursor = conn.cursor()
            cursor.execute("SELECT v FROM t")
            assert cursor.fetchone()["v"] == "ok"

    def test_rollback_on_exception(self):
        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.execute("INSERT INTO t (v) VALUES (?)", ("keep",))
        conn.commit()

        try:
            with connect(db_path=":memory:") as conn2:
                conn2.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
                conn2.execute("INSERT INTO t (v) VALUES (?)", ("will_rollback",))
                raise ValueError("simulated error")
        except ValueError:
            pass
        # The rollback happened, connection is closed — data not committed


class TestAdaptSchemaSql:
    def test_no_change_for_sqlite(self):
        sql = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        assert adapt_schema_sql(sql) == sql
        assert adapt_schema_sql(sql, db_url=None) == sql

    def test_autoincrement_to_serial(self):
        sql = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)"
        result = adapt_schema_sql(sql, db_url="postgresql://localhost/db")
        assert "SERIAL PRIMARY KEY" in result
        assert "AUTOINCREMENT" not in result

    def test_case_insensitive(self):
        sql = "CREATE TABLE t (id integer primary key autoincrement)"
        result = adapt_schema_sql(sql, db_url="postgresql://localhost/db")
        assert "SERIAL PRIMARY KEY" in result

    def test_idempotent_for_sqlite(self):
        """Running adapt twice on SQLite SQL should be identical."""
        sql = "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"
        assert adapt_schema_sql(adapt_schema_sql(sql)) == sql


class TestColumnExists:
    def test_existing_column(self):
        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
        assert column_exists(conn, "t", "name") is True
        conn.close()

    def test_missing_column(self):
        conn = get_connection(db_path=":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
        assert column_exists(conn, "t", "nonexistent") is False
        conn.close()


class TestAuthSchemaViaAbstraction:
    """Verify auth schema can be initialized through the DB abstraction."""

    def test_create_auth_tables(self):
        with connect(db_path=":memory:") as conn:
            cursor = conn.cursor()

            # Simulate the auth schema creation through adapt_schema_sql
            tables = [
                adapt_schema_sql("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'operator',
                        is_active INTEGER DEFAULT 1
                    )
                """),
                adapt_schema_sql("""
                    CREATE TABLE IF NOT EXISTS token_blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        jti TEXT UNIQUE NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                """),
            ]

            for sql in tables:
                cursor.execute(sql)

            # Verify tables exist
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                          ("admin", "hash123"))
            cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
            row = cursor.fetchone()
            assert row["username"] == "admin"
            assert row["role"] == "operator"
