"""
auth.py
-------
SQLite-backed authentication with bcrypt password hashing.

Public API
----------
init_db()                            → create tables + seed default admin
verify_user(username, password)      → bool
get_user_role(username)              → str | None
add_user(username, password, role)   → None
get_all_users()                      → list[dict]
delete_user(username)                → None
update_password(username, password)  → None
get_tour_completed(username)         → bool
set_tour_completed(username, completed) → None
check_login_rate_limit(username)   → tuple[bool, str | None]
record_failed_login(username)      → None
clear_login_attempts(username)     → None
"""

import os
import sqlite3

import bcrypt

from src.db.migrations import migrate_auth_database

_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "users.db")
)

VALID_ROLES = {"admin", "teacher"}


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_DB_PATH, check_same_thread=False)


def _hash_password(password: str) -> str:
    """Return a bcrypt hash for the given password."""
    return bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt(10),
    ).decode()


def _validate_username(username: str) -> str:
    username = str(username).strip().lower()
    if not username:
        raise ValueError("Username cannot be empty.")
    return username


def _validate_password(password: str) -> str:
    password = str(password)
    if len(password.strip()) < 5:
        raise ValueError("Password must be at least 5 characters long.")
    return password


def _validate_role(role: str) -> str:
    role = str(role).strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    return role


def init_db() -> None:
    """Create or upgrade users.db and seed the default administrator."""
    with _connect() as conn:
        migrate_auth_database(conn)

        row = conn.execute(
            "SELECT COUNT(1) FROM users WHERE username = ?",
            ("admin",),
        ).fetchone()
        exists = bool(row and row[0])

        if not exists:
            hashed = _hash_password("admin123")
            conn.execute(
                """
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
                """,
                ("admin", hashed, "admin"),
            )
            conn.commit()


def verify_user(username: str, password: str) -> bool:
    """Return True if username exists and password matches the stored hash."""
    username = _validate_username(username)
    password = _validate_password(password)

    with _connect() as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row:
        return False

    return bcrypt.checkpw(password.encode(), row[0].encode())


# Alias for compatibility
authenticate_user = verify_user


def get_user_role(username: str) -> str | None:
    """Return the role of a user, or None if not found."""
    username = _validate_username(username)

    with _connect() as conn:
        row = conn.execute(
            "SELECT role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    return row[0] if row else None


def add_user(username: str, password: str, role: str = "teacher") -> None:
    """Insert a user and preserve SQLite duplicate-user semantics."""
    username = _validate_username(username)
    password = _validate_password(password)
    role = _validate_role(role)

    hashed = _hash_password(password)

    with _connect() as conn:
        # The UNIQUE constraint is the source of truth. Existing callers and
        # tests rely on sqlite3.IntegrityError for duplicate usernames.
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed, role),
        )
        conn.commit()


def get_all_users() -> list:
    """Return all users as a list of dicts (excludes password hashes)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, username, role FROM users ORDER BY id"
        ).fetchall()

    return [
        {
            "id": row[0],
            "username": row[1],
            "role": row[2],
        }
        for row in rows
    ]


def delete_user(username: str) -> None:
    """Delete a user by username."""
    username = _validate_username(username)

    with _connect() as conn:
        conn.execute(
            "DELETE FROM users WHERE username = ?",
            (username,),
        )
        conn.commit()


def update_password(username: str, new_password: str) -> None:
    """Update a user's password with a new bcrypt hash."""
    username = _validate_username(username)
    new_password = _validate_password(new_password)

    with _connect() as conn:
        # Optimized check using COUNT(1) for #185
        cursor = conn.execute(
            "SELECT COUNT(1) FROM users WHERE username = ?",
            (username,),
        )
        if cursor.fetchone()[0] == 0:
            raise ValueError("User not found.")

        hashed = _hash_password(new_password)
        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed, username),
        )
        conn.commit()


def get_tour_completed(username: str) -> bool:
    """Return whether a user has completed the onboarding tour."""
    username = _validate_username(username)

    with _connect() as conn:
        row = conn.execute(
            "SELECT tour_completed FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    return bool(row[0]) if row else False


def set_tour_completed(username: str, completed: bool = True) -> None:
    """Mark a user as having completed the onboarding tour."""
    username = _validate_username(username)

    with _connect() as conn:
        conn.execute(
            "UPDATE users SET tour_completed = ? WHERE username = ?",
            (1 if completed else 0, username),
        )
        conn.commit()


def get_2fa_status(username: str) -> tuple[bool, str | None]:
    """Return (two_factor_enabled, otp_secret) for a user."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT two_factor_enabled, otp_secret FROM users WHERE username = ?",
            (username.lower(),),
        ).fetchone()
    if not row:
        return False, None
    return bool(row[0]), row[1]


def enable_2fa(username: str, secret: str) -> None:
    """Enable 2FA for a user and store their OTP secret."""
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET two_factor_enabled = 1, otp_secret = ? WHERE username = ?",
            (secret, username.lower()),
        )
        conn.commit()


def disable_2fa(username: str) -> None:
    """Disable 2FA for a user and clear their OTP secret."""
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET two_factor_enabled = 0, otp_secret = NULL WHERE username = ?",
            (username.lower(),),
        )
        conn.commit()


def check_login_rate_limit(username: str) -> tuple[bool, str | None]:
    """Check if username is rate limited. Returns (is_allowed, error_message)."""
    from src.utils.redis_cache import is_login_locked_out, get_login_attempts
    
    identifier = username.lower()
    if is_login_locked_out(identifier):
        attempts = get_login_attempts(identifier)
        return False, f"Account locked due to too many failed attempts. Please try again in 15 minutes. ({attempts}/5 attempts)"
    return True, None


def record_failed_login(username: str) -> None:
    """Record a failed login attempt for rate limiting."""
    from src.utils.redis_cache import increment_login_attempts
    identifier = username.lower()
    increment_login_attempts(identifier)


def clear_login_attempts(username: str) -> None:
    """Clear failed login attempts after successful login."""
    from src.utils.redis_cache import clear_login_attempts as redis_clear_login_attempts
    identifier = username.lower()
    redis_clear_login_attempts(identifier)
