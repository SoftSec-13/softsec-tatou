"""Flask app and SQLite database initialization for fuzzing."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .env import configure_environment, get_temp_root

if TYPE_CHECKING:
    from flask import Flask
    from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_APP: Flask | None = None
_TEST_ENGINE: Engine | None = None


def init_test_db() -> Engine | None:
    """Initialize ephemeral SQLite database that mimics production schema.

    Returns:
        SQLAlchemy engine or None on failure

    The database includes:
    - Users table
    - Documents table
    - Versions table
    - Custom SQL functions (UNHEX, LAST_INSERT_ID)
    """
    global _TEST_ENGINE

    if _TEST_ENGINE is not None:
        return _TEST_ENGINE

    configure_environment()

    try:
        from sqlalchemy import create_engine, event, text
        from sqlalchemy.pool import StaticPool

        temp_root = get_temp_root()
        db_path = temp_root / "tatou_fuzz.sqlite"

        engine: Engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            future=True,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        # Register MariaDB compatibility functions
        @event.listens_for(engine, "connect")
        def _register_functions(dbapi_conn, _) -> None:  # type: ignore[override]
            def _unhex(value: str | None) -> bytes | None:
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

        # Create schema
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

        _TEST_ENGINE = engine
        logger.debug(f"Initialized test database at {db_path}")
        return engine

    except Exception as exc:
        logger.warning(f"Failed to initialize test DB: {exc}", exc_info=True)
        _TEST_ENGINE = None
        return None


def get_test_engine() -> Engine | None:
    """Get the test database engine."""
    return _TEST_ENGINE


def get_app() -> Flask:
    """Get singleton Flask app configured for fuzzing.

    Returns:
        Flask app with testing mode enabled and ephemeral SQLite database
    """
    global _APP

    if _APP is not None:
        return _APP

    engine = init_test_db()

    from server import create_app

    _APP = create_app()
    _APP.testing = True

    if engine is not None:
        _APP.config["_ENGINE"] = engine

    logger.debug("Initialized Flask app for fuzzing")

    return _APP
