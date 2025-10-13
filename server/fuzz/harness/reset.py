"""State reset utilities for deterministic fuzzing."""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import tempfile
from pathlib import Path

from .env import get_storage_dir, get_temp_root

logger = logging.getLogger(__name__)


def make_temp_file(suffix: str = ".pdf") -> Path:
    """Create a temporary file in the fuzzing temp directory.

    Args:
        suffix: File extension

    Returns:
        Path to temporary file
    """
    temp_root = get_temp_root()
    fd, path = tempfile.mkstemp(suffix=suffix, dir=temp_root)
    os.close(fd)
    return Path(path)


def cleanup_storage() -> None:
    """Clean storage directory and database state for next iteration.

    This function ensures deterministic state by:
    - Removing all files from storage directory
    - Clearing all database tables

    Errors are logged but do not crash the fuzzer.
    """
    storage_dir = get_storage_dir()

    # Clean filesystem
    for item in storage_dir.iterdir():
        try:
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)
        except Exception as exc:
            logger.debug(f"Failed to remove {item}: {exc}")

    # Clean database
    from .app import get_test_engine

    engine = get_test_engine()
    if engine is not None:
        try:
            from sqlalchemy import text

            with engine.begin() as conn:
                conn.execute(text("DELETE FROM Versions"))
                conn.execute(text("DELETE FROM Documents"))
                conn.execute(text("DELETE FROM Users"))
        except Exception as exc:
            logger.debug(f"DB cleanup failed: {exc}")


@atexit.register
def _cleanup_temp_on_exit() -> None:
    """Remove all temp files on process exit."""
    try:
        temp_root = get_temp_root()
        shutil.rmtree(temp_root, ignore_errors=True)
        logger.debug(f"Cleaned up temp directory: {temp_root}")
    except Exception:
        pass
