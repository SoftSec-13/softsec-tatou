#!/usr/bin/env python3
"""Function-level fuzzer for watermarking_utils.explore_pdf.

This target exercises PDF parsing directly without Flask overhead,
enabling faster iterations and deeper coverage of PDF structure handling.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add fuzz directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import atheris

with atheris.instrument_imports():
    from harness import configure_environment

    configure_environment()

    import watermarking_utils as wm

logger = logging.getLogger(__name__)


def fuzz_one_input(data: bytes) -> None:
    """Fuzz explore_pdf with raw bytes.

    Args:
        data: Raw fuzzed bytes to parse as PDF
    """
    if not data or len(data) < 10:
        return

    try:
        # explore_pdf handles bytes or file paths
        result = wm.explore_pdf(data)

        # Basic sanity checks
        if not isinstance(result, dict):
            raise AssertionError("explore_pdf must return dict")

        if "type" not in result or result["type"] != "Document":
            raise AssertionError("explore_pdf result must have type=Document")

        if "id" not in result:
            raise AssertionError("explore_pdf result must have id field")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        # Expected exceptions from malformed PDFs
        logger.debug(f"explore_pdf iteration failed: {exc}")


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
