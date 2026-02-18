"""
Auth database schema initialization and migrations.

IMPORTANT: _init_database() should ONLY be called by:
- dashboard/api_server.py at startup
- Test fixtures

Never call schema initialization from feature code (routes, decorators, etc.).
"""
import os
import sqlite3
import logging

from werkzeug.security import generate_password_hash

from core.db import adapt_schema_sql, column_exists
from .config import (
    DB_PATH,
    DEFAULT_PERMISSIONS,
    DEFAULT_GROUPS,
)
from . import database

logger = logging.getLogger(__name__)

# Database URL for schema adaptation
_DB_URL = database._AUTH_DB_URL


def _init_database():
    """Initialize the database with all required tables."""
    conn = database._get_db_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute(adapt_schema_sql("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            is_active INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            password_change_required INTEGER DEFAULT 0,
            saml_uid TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'local',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """, _DB_URL))

    # Create token blacklist table
    cursor.execute(adapt_schema_sql("""
        CREATE TABLE IF NOT EXISTS token_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """, _DB_URL))

    # Create permissions table
    cursor.execute(adapt_schema_sql("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """, _DB_URL))

    # Create groups table
    cursor.execute(adapt_schema_sql("""
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """, _DB_URL))

    # Create group_permissions junction table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS group_permissions (
            group_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, permission_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
    """)

    # Create user_groups junction table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, group_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    """)

    # Run migrations
    _run_migrations(cursor)

    conn.commit()

    # Seed default data
    _seed_default_data(cursor, conn)

    conn.close()


def _run_migrations(cursor):
    """Run any pending database migrations."""
    conn = database._get_db_connection()

    # Migration: Add saml_uid and auth_provider columns
    if not column_exists(conn, "users", "saml_uid", _DB_URL):
        cursor.execute("ALTER TABLE users ADD COLUMN saml_uid TEXT UNIQUE")
        cursor.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'")
        logger.info("Migration: Added SAML columns to users table")

    # Migration: Add password_change_required column
    if not column_exists(conn, "users", "password_change_required", _DB_URL):
        cursor.execute("ALTER TABLE users ADD COLUMN password_change_required INTEGER DEFAULT 0")
        logger.info("Migration: Added password_change_required column")

    conn.close()


def _seed_default_data(cursor, conn):
    """Seed default permissions, groups, and admin user."""
    # Seed permissions
    for perm_name, perm_desc in DEFAULT_PERMISSIONS:
        try:
            cursor.execute(
                "INSERT INTO permissions (name, description) VALUES (?, ?)",
                (perm_name, perm_desc)
            )
        except sqlite3.IntegrityError:
            pass  # Already exists

    conn.commit()

    # Seed default groups
    for group_name, group_data in DEFAULT_GROUPS.items():
        try:
            cursor.execute(
                "INSERT INTO groups (name, description) VALUES (?, ?)",
                (group_name, group_data["description"])
            )
            group_id = cursor.lastrowid

            # Assign permissions to group
            for perm_name in group_data["permissions"]:
                cursor.execute("SELECT id FROM permissions WHERE name = ?", (perm_name,))
                perm_row = cursor.fetchone()
                if perm_row:
                    cursor.execute(
                        "INSERT INTO group_permissions (group_id, permission_id) VALUES (?, ?)",
                        (group_id, perm_row["id"])
                    )
        except sqlite3.IntegrityError:
            pass  # Already exists

    conn.commit()

    # Create default admin user if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        from config.vault_client import get_admin_password
        default_password = get_admin_password()
        password_hash = generate_password_hash(default_password)

        # Mark password change required if using default password
        # Skip in demo mode — don't gate the UI behind a password change flow
        from core.demo import DEMO_MODE
        password_change_required = 0 if DEMO_MODE else (1 if default_password == "admin" else 0)

        cursor.execute(
            """INSERT INTO users (username, password_hash, role, password_change_required)
               VALUES (?, ?, 'admin', ?)""",
            ("admin", password_hash, password_change_required)
        )
        admin_id = cursor.lastrowid

        # Assign admin to Network Admins group
        cursor.execute("SELECT id FROM groups WHERE name = 'Network Admins'")
        admin_group = cursor.fetchone()
        if admin_group:
            cursor.execute(
                "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
                (admin_id, admin_group["id"])
            )

        conn.commit()
        logger.info("Default admin user created")


def _load_users_from_env() -> dict:
    """Load users from environment (fallback when SQLite unavailable)."""
    users = {}
    users_env = os.getenv("DASHBOARD_USERS")
    if users_env:
        for user_entry in users_env.split(","):
            parts = user_entry.strip().split(":")
            if len(parts) == 3:
                username, password_hash, role = parts
                users[username] = {
                    "password_hash": password_hash,
                    "role": role
                }
    return users


def initialize():
    """Initialize database and set module state.

    Call this once from api_server.py startup.
    """
    try:
        _init_database()
        database.USE_SQLITE = True
        print(f"User database initialized: {DB_PATH}")
    except Exception as e:
        print(f"WARNING: SQLite init failed ({e}), falling back to env-based users")
        database.USE_SQLITE = False

    # Load fallback users regardless (for fallback mode)
    database.ENV_USERS = _load_users_from_env()
