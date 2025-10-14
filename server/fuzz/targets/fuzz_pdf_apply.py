#!/usr/bin/env python3
"""Per-method fuzzer for apply_watermark across all registered methods.

This target iterates through all watermarking methods and applies them
to fuzzed PDFs, enabling method-specific crash discovery.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add fuzz directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import atheris

with atheris.instrument_imports():
    from harness import configure_environment, make_temp_file

    configure_environment()

    import watermarking_utils as wm

logger = logging.getLogger(__name__)

PDF_MAX_BYTES = 100_000


def fuzz_one_input(data: bytes) -> None:
    """Fuzz apply_watermark with raw PDF bytes across all methods.

    Args:
        data: Fuzzed bytes for PDF content, secret, and key
    """
    if not data or len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Select method
    methods = list(wm.METHODS.keys())
    if not methods:
        return

    method = (
        methods[fdp.ConsumeIntInRange(0, len(methods) - 1)]
        if len(methods) > 1
        else methods[0]
    )

    # Extract PDF bytes
    pdf_size = min(fdp.ConsumeIntInRange(10, PDF_MAX_BYTES), fdp.remaining_bytes() - 20)
    pdf_bytes = fdp.ConsumeBytes(pdf_size) or b"%PDF-1.4\n%%EOF\n"

    # Ensure minimal PDF structure
    if not pdf_bytes.startswith(b"%PDF"):
        pdf_bytes = b"%PDF-1.4\n" + pdf_bytes

    # Consume secret and key
    secret = fdp.ConsumeUnicodeNoSurrogates(128) or "fuzz-secret"
    key = fdp.ConsumeUnicodeNoSurrogates(128) or "fuzz-key"
    intended_for = fdp.ConsumeUnicodeNoSurrogates(128) or "fuzzer@test.com"

    pdf_path = make_temp_file()
    pdf_path.write_bytes(pdf_bytes)

    try:
        result = wm.apply_watermark(
            method=method,
            pdf=str(pdf_path),
            secret=secret,
            key=key,
            intended_for=intended_for,
        )

        # Validate result
        if not isinstance(result, bytes | bytearray):
            raise AssertionError(
                f"apply_watermark must return bytes, got {type(result)}"
            )

        if len(result) == 0:
            raise AssertionError("apply_watermark returned empty bytes")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        # Expected exceptions from malformed PDFs
        logger.debug(f"apply_watermark iteration failed for {method}: {exc}")
    finally:
        pdf_path.unlink(missing_ok=True)


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
