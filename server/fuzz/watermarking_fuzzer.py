#!/usr/bin/env python3
"""PDF watermarking fuzzer - Tests PDF parsing and watermark operations.

This fuzzer generates various PDF structures to test:
- Valid PDFs
- JavaScript payloads (XSS test)
- Deeply nested objects (stack overflow)
- Large streams (memory exhaustion)
- Malicious annotations
- Malformed PDFs
"""

import logging
import sys

import atheris

with atheris.instrument_imports():
    from utils import generate_fuzzed_pdf, make_temp_file

    import watermarking_utils as wm

logger = logging.getLogger(__name__)


def fuzz_one_input(data: bytes) -> None:
    """Fuzz watermarking methods with various PDF structures.

    Args:
        data: Raw bytes from fuzzer
    """
    if len(data) < 32:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create PDF using extracted generator
    pdf_bytes = generate_fuzzed_pdf(fdp)
    pdf_path = make_temp_file()
    pdf_path.write_bytes(pdf_bytes)

    # Get watermarking method
    methods = list(wm.METHODS.keys())
    if not methods:
        return
    method = methods[fdp.ConsumeIntInRange(0, len(methods) - 1)]

    secret = fdp.ConsumeUnicodeNoSurrogates(64)
    key = fdp.ConsumeUnicodeNoSurrogates(64)

    try:
        if not secret or not key:
            return

        # Apply watermark
        result = wm.apply_watermark(
            method=method,
            pdf=str(pdf_path),
            secret=secret,
            key=key,
            intended_for="fuzzer",
        )

        if not isinstance(result, bytes | bytearray):
            raise AssertionError("apply_watermark must return bytes")

        if not result.startswith(b"%PDF"):
            raise AssertionError("Watermarked PDF must start with %PDF")

        # Read watermark
        out_path = make_temp_file()
        out_path.write_bytes(result)

        try:
            wm.read_watermark(method, str(out_path), key)
        finally:
            out_path.unlink(missing_ok=True)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug("Watermark fuzz failed: %s", exc, exc_info=True)
    finally:
        pdf_path.unlink(missing_ok=True)


def main() -> None:
    """Entry point for fuzzer."""
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
