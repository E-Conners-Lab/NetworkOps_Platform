"""
Multi-Factor Authentication (MFA) Module

Implements TOTP-based MFA (RFC 6238) compatible with Google Authenticator,
Authy, and other TOTP apps.

Features:
- TOTP secret generation and validation
- QR code generation for easy enrollment
- Recovery codes for account recovery
- Encrypted secret storage
"""

import os
import hashlib
import secrets
import base64
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from dataclasses import dataclass

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken

from core.db import DatabaseManager

# Configuration
MFA_ENABLED = os.getenv("MFA_ENABLED", "true").lower() == "true"
MFA_ISSUER_NAME = os.getenv("MFA_ISSUER_NAME", "NetworkOps")
RECOVERY_CODE_COUNT = 8  # Number of recovery codes to generate


def _get_encryption_key() -> bytes:
    """Get or generate the MFA encryption key.

    Priority:
    1. MFA_ENCRYPTION_KEY env var (must be valid Fernet key)
    2. Derived from settings JWT secret (works but logged as warning)

    Returns:
        Fernet-compatible encryption key
    """
    import logging as _logging
    _logger = _logging.getLogger(__name__)

    from config.vault_client import get_mfa_encryption_key
    key = get_mfa_encryption_key()
    if key:
        # Validate it's a valid Fernet key
        try:
            Fernet(key.encode() if isinstance(key, str) else key)
            return key.encode() if isinstance(key, str) else key
        except Exception:
            pass

    # Derive from the settings JWT secret (which is either env-provided or random)
    from config.settings import get_settings
    jwt_secret = get_settings().auth.jwt_secret.get_secret_value()
    _logger.warning("MFA_ENCRYPTION_KEY not set — deriving from JWT secret. Set MFA_ENCRYPTION_KEY for production.")
    derived = hashlib.sha256(jwt_secret.encode()).digest()
    return base64.urlsafe_b64encode(derived)


def _get_fernet() -> Fernet:
    """Get Fernet cipher for encryption/decryption."""
    return Fernet(_get_encryption_key())


def _get_db_connection():
    """Get database connection from the consolidated pool."""
    return DatabaseManager.get_instance().get_connection()


def init_mfa_tables():
    """Create MFA-related tables if they don't exist."""
    conn = _get_db_connection()
    cursor = conn.cursor()

    # User MFA settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_mfa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            totp_secret_encrypted TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            confirmed_at TEXT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Recovery codes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            used_at TEXT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Indexes
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id)"
    )

    conn.commit()
    conn.close()


@dataclass
class MFAStatus:
    """MFA status for a user."""

    is_enabled: bool
    is_setup: bool  # Has TOTP secret but not confirmed
    recovery_codes_remaining: int


class MFAManager:
    """Manages MFA operations for users."""

    def get_mfa_status(self, user_id: int) -> MFAStatus:
        """Get MFA status for a user.

        Args:
            user_id: User's database ID

        Returns:
            MFAStatus with current MFA state
        """
        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT is_enabled, confirmed_at FROM user_mfa WHERE user_id = ?",
            (user_id,),
        )
        mfa_row = cursor.fetchone()

        cursor.execute(
            "SELECT COUNT(*) as count FROM mfa_recovery_codes WHERE user_id = ? AND is_used = 0",
            (user_id,),
        )
        recovery_row = cursor.fetchone()

        conn.close()

        if not mfa_row:
            return MFAStatus(
                is_enabled=False, is_setup=False, recovery_codes_remaining=0
            )

        return MFAStatus(
            is_enabled=bool(mfa_row["is_enabled"]),
            is_setup=mfa_row["confirmed_at"] is None and mfa_row["is_enabled"] == 0,
            recovery_codes_remaining=recovery_row["count"] if recovery_row else 0,
        )

    def setup_mfa(self, user_id: int, username: str) -> tuple[str, str]:
        """Begin MFA setup for a user.

        Generates a new TOTP secret and returns QR code for enrollment.

        Args:
            user_id: User's database ID
            username: Username for display in authenticator app

        Returns:
            Tuple of (secret for manual entry, base64-encoded QR code PNG)
        """
        # Generate new TOTP secret
        totp_secret = pyotp.random_base32()

        # Encrypt the secret for storage
        fernet = _get_fernet()
        encrypted_secret = fernet.encrypt(totp_secret.encode()).decode()

        conn = _get_db_connection()
        cursor = conn.cursor()

        # Check if user already has MFA setup
        cursor.execute("SELECT id FROM user_mfa WHERE user_id = ?", (user_id,))
        existing = cursor.fetchone()

        if existing:
            # Update existing record (re-enrollment)
            cursor.execute(
                """
                UPDATE user_mfa
                SET totp_secret_encrypted = ?, is_enabled = 0, confirmed_at = NULL,
                    created_at = ?
                WHERE user_id = ?
                """,
                (encrypted_secret, datetime.now(timezone.utc).isoformat(), user_id),
            )
            # Delete old recovery codes
            cursor.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
        else:
            # Insert new record
            cursor.execute(
                """
                INSERT INTO user_mfa (user_id, totp_secret_encrypted, is_enabled, created_at)
                VALUES (?, ?, 0, ?)
                """,
                (user_id, encrypted_secret, datetime.now(timezone.utc).isoformat()),
            )

        conn.commit()
        conn.close()

        # Generate QR code
        totp = pyotp.TOTP(totp_secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name=MFA_ISSUER_NAME)

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return totp_secret, f"data:image/png;base64,{qr_base64}"

    def confirm_mfa(self, user_id: int, totp_code: str) -> tuple[bool, list[str]]:
        """Confirm MFA setup with a TOTP code.

        Args:
            user_id: User's database ID
            totp_code: 6-digit TOTP code from authenticator app

        Returns:
            Tuple of (success, list of recovery codes)
        """
        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT totp_secret_encrypted, is_enabled FROM user_mfa WHERE user_id = ?",
            (user_id,),
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return False, []

        if row["is_enabled"]:
            conn.close()
            return False, []  # Already enabled

        # Decrypt and verify
        try:
            fernet = _get_fernet()
            totp_secret = fernet.decrypt(row["totp_secret_encrypted"].encode()).decode()
        except InvalidToken:
            conn.close()
            return False, []

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            conn.close()
            return False, []

        # Enable MFA
        cursor.execute(
            """
            UPDATE user_mfa
            SET is_enabled = 1, confirmed_at = ?
            WHERE user_id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), user_id),
        )

        # Generate recovery codes
        recovery_codes = []
        for _ in range(RECOVERY_CODE_COUNT):
            code = secrets.token_hex(8).upper()  # 16 character hex code (64 bits)
            recovery_codes.append(code)

            # Hash the code for storage
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            cursor.execute(
                """
                INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (user_id, code_hash, datetime.now(timezone.utc).isoformat()),
            )

        conn.commit()
        conn.close()

        return True, recovery_codes

    def verify_totp(self, user_id: int, totp_code: str) -> bool:
        """Verify a TOTP code for login.

        Args:
            user_id: User's database ID
            totp_code: 6-digit TOTP code

        Returns:
            True if code is valid
        """
        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT totp_secret_encrypted, is_enabled FROM user_mfa WHERE user_id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row or not row["is_enabled"]:
            return False

        try:
            fernet = _get_fernet()
            totp_secret = fernet.decrypt(row["totp_secret_encrypted"].encode()).decode()
        except InvalidToken:
            return False

        totp = pyotp.TOTP(totp_secret)
        return totp.verify(totp_code, valid_window=1)

    def verify_recovery_code(self, user_id: int, recovery_code: str) -> bool:
        """Verify and consume a recovery code.

        Args:
            user_id: User's database ID
            recovery_code: Recovery code to verify

        Returns:
            True if code is valid and was consumed
        """
        code_hash = hashlib.sha256(recovery_code.upper().encode()).hexdigest()

        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id FROM mfa_recovery_codes
            WHERE user_id = ? AND code_hash = ? AND is_used = 0
            """,
            (user_id, code_hash),
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return False

        # Mark as used
        cursor.execute(
            """
            UPDATE mfa_recovery_codes
            SET is_used = 1, used_at = ?
            WHERE id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), row["id"]),
        )

        conn.commit()
        conn.close()

        return True

    def disable_mfa(self, user_id: int, totp_code: str) -> bool:
        """Disable MFA for a user.

        Requires a valid TOTP code to disable.

        Args:
            user_id: User's database ID
            totp_code: Current valid TOTP code

        Returns:
            True if MFA was disabled
        """
        # Verify TOTP first
        if not self.verify_totp(user_id, totp_code):
            return False

        conn = _get_db_connection()
        cursor = conn.cursor()

        # Delete MFA record
        cursor.execute("DELETE FROM user_mfa WHERE user_id = ?", (user_id,))

        # Delete recovery codes
        cursor.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))

        conn.commit()
        conn.close()

        return True

    def is_mfa_required(self, user_id: int) -> bool:
        """Check if MFA is required for a user.

        Args:
            user_id: User's database ID

        Returns:
            True if user has MFA enabled and must verify
        """
        if not MFA_ENABLED:
            return False

        conn = _get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT is_enabled FROM user_mfa WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        conn.close()

        return bool(row and row["is_enabled"])


# Singleton instance
_mfa_manager: Optional[MFAManager] = None
_tables_initialized = False


def _ensure_tables():
    """Lazy table initialization on first DB operation."""
    global _tables_initialized
    if not _tables_initialized:
        init_mfa_tables()
        _tables_initialized = True


def get_mfa_manager() -> MFAManager:
    """Get or create MFAManager singleton."""
    global _mfa_manager
    if _mfa_manager is None:
        _ensure_tables()
        _mfa_manager = MFAManager()
    return _mfa_manager
