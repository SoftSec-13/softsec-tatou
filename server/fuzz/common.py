#!/usr/bin/env python3
"""Shared utilities for fuzzing harnesses."""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from itsdangerous import URLSafeTimedSerializer

if TYPE_CHECKING:
    from atheris import FuzzedDataProvider

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Disable RMAP for fuzzing
os.environ.setdefault("TATOU_TEST_DISABLE_RMAP", "1")

# Temp storage
_TEMP_ROOT = Path(tempfile.mkdtemp(prefix="fuzz-", dir="/tmp"))
_STORAGE_DIR = _TEMP_ROOT / "storage"
_STORAGE_DIR.mkdir(exist_ok=True)
os.environ["STORAGE_DIR"] = str(_STORAGE_DIR)

_APP = None
_DB_INITIALIZED = False


def init_test_db():
    """Initialize in-memory test database with minimal schema."""
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return

    try:
        from sqlalchemy import create_engine, text

        # Use SQLite in-memory for fuzzing (no actual MariaDB needed)
        engine = create_engine("sqlite:///:memory:", echo=False)

        with engine.begin() as conn:
            # Minimal schema for fuzzing
            conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS Users (
                    id INTEGER PRIMARY KEY,
                    login TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    ownerid INTEGER
                )
            """)
            )
            conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS Documents (
                    id INTEGER PRIMARY KEY,
                    ownerid INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    sha256 BLOB,
                    upload_ts DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            )

            # Insert test user
            conn.execute(
                text("""
                INSERT OR IGNORE INTO Users (id, login, email, password_hash, ownerid)
                VALUES (1, 'fuzzer', 'fuzzer@test.local', 'dummy_hash', 1)
            """)
            )

        _DB_INITIALIZED = True
    except Exception:
        # If DB init fails, fuzzing can continue without it
        pass


def get_app():
    """Get singleton Flask test app."""
    global _APP
    if _APP is None:
        from server import create_app

        # Initialize test DB first
        init_test_db()

        _APP = create_app()
        _APP.testing = True
    return _APP


def make_auth_header(uid: int = 1, login: str = "fuzzer") -> str:
    """Create valid Bearer token."""
    app = get_app()
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps(
        {"uid": uid, "login": login, "email": f"{login}@fuzz.test"}
    )
    return f"Bearer {token}"


def make_fuzzed_auth(fdp: FuzzedDataProvider) -> str:
    """Create fuzzed auth header (valid or malformed)."""
    if fdp.ConsumeBool():
        uid = fdp.ConsumeIntInRange(1, 999999)
        login = fdp.ConsumeUnicodeNoSurrogates(32) or "fuzzer"
        return make_auth_header(uid, login[:64])

    # Return malformed
    token = fdp.ConsumeUnicodeNoSurrogates(128)
    return f"Bearer {token}" if fdp.ConsumeBool() else token


def make_temp_file(suffix: str = ".pdf") -> Path:
    """Create temp file path."""
    fd, path = tempfile.mkstemp(suffix=suffix, dir=_TEMP_ROOT)
    os.close(fd)
    return Path(path)


def cleanup_storage() -> None:
    """Clean storage directory."""
    for item in _STORAGE_DIR.iterdir():
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)


@atexit.register
def _cleanup():
    """Clean up on exit."""
    shutil.rmtree(_TEMP_ROOT, ignore_errors=True)
