#!/usr/bin/env python3
"""Per-method fuzzer for read_watermark across all registered methods.

This target tests watermark reading by:
1. Applying a watermark with known secret/key
2. Attempting to read it back with fuzzed keys
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

PDF_MAX_BYTES = 50_000
KNOWN_SECRET = "known-secret"
KNOWN_KEY = "known-key"


def fuzz_one_input(data: bytes) -> None:
    """Fuzz read_watermark by creating and reading watermarked PDFs.

    Args:
        data: Fuzzed bytes for PDF content and read key
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
    pdf_size = min(fdp.ConsumeIntInRange(10, PDF_MAX_BYTES), fdp.remaining_bytes() - 10)
    pdf_bytes = fdp.ConsumeBytes(pdf_size) or b"%PDF-1.4\n%%EOF\n"

    if not pdf_bytes.startswith(b"%PDF"):
        pdf_bytes = b"%PDF-1.4\n" + pdf_bytes

    input_pdf = make_temp_file()
    input_pdf.write_bytes(pdf_bytes)

    try:
        # First apply watermark with known credentials
        watermarked_bytes = wm.apply_watermark(
            method=method,
            pdf=str(input_pdf),
            secret=KNOWN_SECRET,
            key=KNOWN_KEY,
            intended_for="fuzzer@test.com",
        )

        if not isinstance(watermarked_bytes, (bytes, bytearray)):
            return  # Skip if apply failed

        # Write watermarked PDF
        output_pdf = make_temp_file()
        output_pdf.write_bytes(bytes(watermarked_bytes))

        # Try reading with fuzzed key
        read_key = fdp.ConsumeUnicodeNoSurrogates(128) or KNOWN_KEY

        try:
            secret = wm.read_watermark(method, str(output_pdf), read_key)

            # If we used the correct key, verify we got the secret back
            if read_key == KNOWN_KEY and secret != KNOWN_SECRET:
                raise AssertionError(
                    f"read_watermark with correct key returned wrong secret: "
                    f"expected {KNOWN_SECRET!r}, got {secret!r}"
                )

        except Exception as read_exc:
            # Reading can fail legitimately (wrong key, malformed PDF)
            logger.debug(f"read_watermark failed: {read_exc}")

        output_pdf.unlink(missing_ok=True)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug(f"watermark cycle failed for {method}: {exc}")
    finally:
        input_pdf.unlink(missing_ok=True)


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
