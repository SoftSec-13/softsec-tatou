"""Environment configuration for fuzzing harness."""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Temp storage
_TEMP_ROOT: Path | None = None
_STORAGE_DIR: Path | None = None


def configure_environment() -> tuple[Path, Path]:
    """Configure environment variables and directories for fuzzing.

    Returns:
        Tuple of (temp_root, storage_dir) paths
    """
    global _TEMP_ROOT, _STORAGE_DIR

    if _TEMP_ROOT is not None and _STORAGE_DIR is not None:
        return (_TEMP_ROOT, _STORAGE_DIR)

    # Add src to path
    src_path = Path(__file__).resolve().parent.parent.parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    # Disable RMAP for fuzzing
    os.environ.setdefault("TATOU_TEST_DISABLE_RMAP", "1")

    # Create temp directories
    _TEMP_ROOT = Path(tempfile.mkdtemp(prefix="fuzz-tatou-"))
    _STORAGE_DIR = _TEMP_ROOT / "storage"
    _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    os.environ["STORAGE_DIR"] = str(_STORAGE_DIR)

    logger.debug(f"Fuzzing environment configured: {_TEMP_ROOT}")

    return (_TEMP_ROOT, _STORAGE_DIR)


def get_temp_root() -> Path:
    """Get temp root directory."""
    if _TEMP_ROOT is None:
        configure_environment()
    assert _TEMP_ROOT is not None
    return _TEMP_ROOT


def get_storage_dir() -> Path:
    """Get storage directory."""
    if _STORAGE_DIR is None:
        configure_environment()
    assert _STORAGE_DIR is not None
    return _STORAGE_DIR
