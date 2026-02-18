"""
Session Management Module

Implements single-session enforcement: each user can have only one active session.
When a user logs in, all previous sessions are automatically invalidated.
"""

import os
import uuid
from datetime import datetime, timezone
from flask import request

from core.db import DatabaseManager

# Feature flag
SINGLE_SESSION_ENABLED = os.getenv("SINGLE_SESSION_ENABLED", "true").lower() == "true"
SESSION_MAX_AGE_HOURS = int(os.getenv("SESSION_MAX_AGE_HOURS", "168"))  # 7 days


def _get_db_connection():
    """Get database connection from the consolidated pool."""
    return DatabaseManager.get_instance().get_connection()


def init_sessions_table():
    """Create the active_sessions table if it doesn't exist."""
    conn = _get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT NOT NULL UNIQUE,
            access_jti TEXT NOT NULL,
            refresh_jti TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_activity TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_sessions_user_id ON active_sessions(user_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_sessions_access_jti ON active_sessions(access_jti)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_active_sessions_refresh_jti ON active_sessions(refresh_jti)"
    )

    conn.commit()
    conn.close()


class SessionManager:
    """Manages user sessions with single-session enforcement."""

    def create_session(
        self,
        user_id: int,
        access_jti: str,
        refresh_jti: str,
    ) -> str:
        """
        Create a new session for a user, invalidating all previous sessions.

        Args:
            user_id: User's database ID
            access_jti: JWT ID of the access token
            refresh_jti: JWT ID of the refresh token

        Returns:
            New session_id
        """
        if not SINGLE_SESSION_ENABLED:
            return str(uuid.uuid4())

        session_id = str(uuid.uuid4())

        # Get request info
        try:
            ip_address = request.remote_addr
            user_agent = request.headers.get("User-Agent", "")[:500]
        except RuntimeError:
            # Not in request context (e.g., testing)
            ip_address = None
            user_agent = None

        # Invalidate all existing sessions for this user
        invalidated_count = self._invalidate_user_sessions(user_id)

        # Create new session
        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO active_sessions
            (user_id, session_id, access_jti, refresh_jti, ip_address, user_agent, created_at, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                session_id,
                access_jti,
                refresh_jti,
                ip_address,
                user_agent,
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        conn.commit()
        conn.close()

        return session_id

    def _invalidate_user_sessions(self, user_id: int) -> int:
        """
        Invalidate all sessions for a user by adding their JTIs to the blacklist.

        Args:
            user_id: User's database ID

        Returns:
            Number of sessions invalidated
        """
        conn = _get_db_connection()
        cursor = conn.cursor()

        # Get all active sessions for user
        cursor.execute(
            "SELECT access_jti, refresh_jti FROM active_sessions WHERE user_id = ?",
            (user_id,),
        )
        sessions = cursor.fetchall()

        if not sessions:
            conn.close()
            return 0

        # Import here to avoid circular dependency
        from dashboard.auth import blacklist_token

        # Blacklist all JTIs
        for session in sessions:
            # Use a far-future expiration for blacklisted tokens
            future_exp = datetime.now(timezone.utc).replace(year=2099)
            if session["access_jti"]:
                blacklist_token(session["access_jti"], future_exp)
            if session["refresh_jti"]:
                blacklist_token(session["refresh_jti"], future_exp)

        # Delete session records
        cursor.execute("DELETE FROM active_sessions WHERE user_id = ?", (user_id,))

        conn.commit()
        conn.close()

        return len(sessions)

    def validate_session(self, jti: str) -> bool:
        """
        Check if a JTI belongs to an active session.

        Args:
            jti: JWT ID to validate

        Returns:
            True if the JTI belongs to an active session
        """
        if not SINGLE_SESSION_ENABLED:
            return True

        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id FROM active_sessions
            WHERE access_jti = ? OR refresh_jti = ?
            """,
            (jti, jti),
        )
        result = cursor.fetchone()
        conn.close()

        return result is not None

    def get_user_session(self, user_id: int) -> dict | None:
        """
        Get the current active session for a user.

        Args:
            user_id: User's database ID

        Returns:
            Session dict or None
        """
        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT session_id, ip_address, user_agent, created_at, last_activity
            FROM active_sessions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "session_id": row["session_id"],
                "ip_address": row["ip_address"],
                "user_agent": row["user_agent"],
                "created_at": row["created_at"],
                "last_activity": row["last_activity"],
            }
        return None

    def update_session_tokens(self, user_id: int, new_access_jti: str, new_refresh_jti: str) -> bool:
        """
        Update the JTIs for a user's active session (used during token refresh).

        Args:
            user_id: User's database ID
            new_access_jti: JTI of the new access token
            new_refresh_jti: JTI of the new refresh token

        Returns:
            True if session was updated
        """
        if not SINGLE_SESSION_ENABLED:
            return True

        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE active_sessions
            SET access_jti = ?, refresh_jti = ?, last_activity = ?
            WHERE user_id = ?
            """,
            (
                new_access_jti,
                new_refresh_jti,
                datetime.now(timezone.utc).isoformat(),
                user_id,
            ),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return updated

    def update_activity(self, jti: str) -> None:
        """
        Update the last_activity timestamp for a session.

        Args:
            jti: JWT ID of the access token
        """
        if not SINGLE_SESSION_ENABLED:
            return

        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE active_sessions
            SET last_activity = ?
            WHERE access_jti = ?
            """,
            (datetime.now(timezone.utc).isoformat(), jti),
        )

        conn.commit()
        conn.close()

    def delete_session(self, user_id: int) -> bool:
        """
        Delete a user's active session (used for logout).

        Args:
            user_id: User's database ID

        Returns:
            True if session was deleted
        """
        return self._invalidate_user_sessions(user_id) > 0

    def cleanup_expired_sessions(self) -> int:
        """
        Remove sessions older than SESSION_MAX_AGE_HOURS.

        Returns:
            Number of sessions cleaned up
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(hours=SESSION_MAX_AGE_HOURS)

        conn = _get_db_connection()
        cursor = conn.cursor()

        # Get sessions to clean up
        cursor.execute(
            "SELECT id, access_jti, refresh_jti FROM active_sessions WHERE created_at < ?",
            (cutoff.isoformat(),),
        )
        expired = cursor.fetchall()

        if not expired:
            conn.close()
            return 0

        # Import here to avoid circular dependency
        from dashboard.auth import blacklist_token

        # Blacklist JTIs
        future_exp = datetime.now(timezone.utc).replace(year=2099)
        for session in expired:
            if session["access_jti"]:
                blacklist_token(session["access_jti"], future_exp)
            if session["refresh_jti"]:
                blacklist_token(session["refresh_jti"], future_exp)

        # Delete expired sessions
        cursor.execute("DELETE FROM active_sessions WHERE created_at < ?", (cutoff.isoformat(),))

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        return deleted


# Singleton instance
_session_manager: SessionManager | None = None
_tables_initialized = False


def _ensure_tables():
    """Lazy table initialization on first DB operation."""
    global _tables_initialized
    if not _tables_initialized:
        init_sessions_table()
        _tables_initialized = True


def get_session_manager() -> SessionManager:
    """Get or create SessionManager singleton."""
    global _session_manager
    if _session_manager is None:
        _ensure_tables()
        _session_manager = SessionManager()
    return _session_manager
