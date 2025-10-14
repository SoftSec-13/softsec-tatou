#!/usr/bin/env python3
"""Sanity-check fuzzer seeds to make sure they match expected schemas.

Run this locally before long fuzzing sessions to confirm curated seeds
are valid. Exits non-zero if any problems are found.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEEDS_ROOT = REPO_ROOT / "seeds"
REST_ALLOWED_EMPTY: set[str] = set()
PDF_ALLOWED_EMPTY: set[str] = {"edge_empty_file.bin"}


class SeedValidationError(RuntimeError):
    """Raised when a seed file does not meet structural expectations."""


def _iter_seed_files(subdir: str) -> Iterable[Path]:
    seed_dir = SEEDS_ROOT / subdir
    if not seed_dir.is_dir():
        raise SeedValidationError(f"Seed directory missing: {seed_dir}")
    yield from sorted(seed_dir.glob("*.bin"))


def _validate_rest_seed(path: Path) -> None:
    """Validate REST API endpoint seeds (JSON payloads)."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SeedValidationError(f"{path}: not valid UTF-8 JSON ({exc})") from exc
    if not isinstance(payload, dict):
        raise SeedValidationError(
            f"{path}: expected JSON object, got {type(payload).__name__}"
        )


def _validate_workflow_seed(path: Path) -> None:
    """Validate workflow seeds (JSON arrays of actions)."""
    try:
        workflow = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SeedValidationError(f"{path}: not valid UTF-8 JSON ({exc})") from exc
    if not isinstance(workflow, list):
        raise SeedValidationError(
            f"{path}: expected JSON array workflow, got {type(workflow).__name__}"
        )
    for index, step in enumerate(workflow):
        if not isinstance(step, dict):
            raise SeedValidationError(
                f"{path}: workflow step {index} is {type(step).__name__}, "
                "expected object"
            )
        action = step.get("action")
        if not isinstance(action, str) or not action:
            raise SeedValidationError(
                f"{path}: workflow step {index} missing non-empty 'action'"
            )


def _validate_pdf_seed(path: Path) -> None:
    """Validate PDF seeds (binary PDF data)."""
    data = path.read_bytes()
    if not data and path.name not in PDF_ALLOWED_EMPTY:
        raise SeedValidationError(f"{path}: seed is empty")


VALIDATORS = {
    "fuzz_rest_endpoints": _validate_rest_seed,
    "fuzz_workflows": _validate_workflow_seed,
    "fuzz_pdf_explore": _validate_pdf_seed,
    "fuzz_pdf_read": _validate_pdf_seed,
    "fuzz_pdf_apply": _validate_pdf_seed,
}


def main() -> int:
    failures: list[str] = []

    for fuzzer, validator in VALIDATORS.items():
        for path in _iter_seed_files(fuzzer):
            try:
                validator(path)
            except SeedValidationError as exc:
                failures.append(str(exc))

    if failures:
        for failure in failures:
            print(f"[ERROR] {failure}")
        return 1

    print("All seeds look structurally sound.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
