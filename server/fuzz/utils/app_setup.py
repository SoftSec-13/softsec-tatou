"""Flask app and database setup for fuzzing.

This module handles the initialization of the Flask application and
an ephemeral SQLite database for fuzzing, along with file system utilities.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

# Disable RMAP for fuzzing
os.environ.setdefault("TATOU_TEST_DISABLE_RMAP", "1")

logger = logging.getLogger(__name__)

# Temp storage setup
_TEMP_ROOT = Path(tempfile.mkdtemp(prefix="fuzz-"))
_STORAGE_DIR = _TEMP_ROOT / "storage"
_STORAGE_DIR.mkdir(exist_ok=True)
os.environ["STORAGE_DIR"] = str(_STORAGE_DIR)

# Global state
_APP = None
_DB_INITIALIZED = False
_TEST_ENGINE = None


def init_test_db():
    """Initialize lightweight SQLite database and return its engine.

    Returns:
        SQLAlchemy engine backed by a temporary SQLite database that mirrors the
        minimum schema expected by the Flask app.
    """
    global _DB_INITIALIZED, _TEST_ENGINE
    if _TEST_ENGINE is not None:
        return _TEST_ENGINE

    try:
        from sqlalchemy import create_engine, event, text
        from sqlalchemy.engine import Engine
        from sqlalchemy.pool import StaticPool

        db_path = _TEMP_ROOT / "tatou_fuzz.sqlite"
        engine: Engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            future=True,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _register_functions(dbapi_conn, _):  # type: ignore[override]
            def _unhex(value: str | None):
                if not value:
                    return None
                try:
                    return bytes.fromhex(value)
                except ValueError:
                    return None

            def _last_insert_id() -> int | None:
                try:
                    cursor = dbapi_conn.execute("SELECT last_insert_rowid()")
                    row = cursor.fetchone()
                    return int(row[0]) if row and row[0] is not None else None
                except Exception:
                    return None

            dbapi_conn.create_function("UNHEX", 1, _unhex)
            dbapi_conn.create_function("LAST_INSERT_ID", 0, _last_insert_id)

        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS Users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        hpassword TEXT NOT NULL,
                        login TEXT UNIQUE NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS Documents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        path TEXT NOT NULL,
                        ownerid INTEGER NOT NULL,
                        sha256 BLOB,
                        size INTEGER NOT NULL,
                        creation DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS Versions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        documentid INTEGER NOT NULL,
                        link TEXT UNIQUE NOT NULL,
                        intended_for TEXT,
                        secret TEXT,
                        method TEXT,
                        position TEXT,
                        path TEXT NOT NULL,
                        FOREIGN KEY(documentid) REFERENCES Documents(id)
                    )
                    """
                )
            )

        _DB_INITIALIZED = True
        _TEST_ENGINE = engine
        return engine
    except Exception as exc:
        logger.warning("[tatou-fuzz] init_test_db fallback: %s", exc, exc_info=True)
        _TEST_ENGINE = None
        return None


def get_app():
    """Get singleton Flask test app.

    Returns:
        Flask app instance configured for testing

    Note:
        The app is created only once and reused across all fuzzing iterations
        for performance. The app.testing flag is set to True.
    """
    global _APP
    engine = init_test_db()

    if _APP is None:
        from server import create_app

        _APP = create_app()
        _APP.testing = True
        if engine is not None:
            _APP.config["_ENGINE"] = engine
    return _APP


def make_temp_file(suffix: str = ".pdf") -> Path:
    """Create a temporary file for fuzzing.

    Args:
        suffix: File extension (default: .pdf)

    Returns:
        Path object pointing to the temporary file

    Note:
        Files are created in the fuzzing temp directory and are
        automatically cleaned up at exit.
    """
    fd, path = tempfile.mkstemp(suffix=suffix, dir=_TEMP_ROOT)
    os.close(fd)
    return Path(path)


def cleanup_storage() -> None:
    """Clean the storage directory.

    Removes all files and directories created during fuzzing to prevent
    accumulation of test data across iterations.
    """
    for item in _STORAGE_DIR.iterdir():
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

    if _TEST_ENGINE is not None:
        try:
            from sqlalchemy import text

            with _TEST_ENGINE.begin() as conn:
                conn.execute(text("DELETE FROM Versions"))
                conn.execute(text("DELETE FROM Documents"))
                conn.execute(text("DELETE FROM Users"))
        except Exception as exc:
            # Database cleanup failures should not crash the fuzzer loop
            logger.debug(
                "Database cleanup failed during fuzz teardown: %s",
                exc,
                exc_info=True,
            )


@atexit.register
def _cleanup() -> None:
    """Clean up temporary files on exit.

    This function is automatically called when the Python process exits,
    ensuring all fuzzing artifacts are removed.
    """
    shutil.rmtree(_TEMP_ROOT, ignore_errors=True)
