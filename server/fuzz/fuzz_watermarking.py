#!/usr/bin/env python3
"""Fuzz PDF watermarking operations."""

import sys

import atheris

with atheris.instrument_imports():
    import watermarking_utils as wm

import common


def make_pdf(fdp: atheris.FuzzedDataProvider) -> bytes:
    """Create fuzzed PDF."""
    version = fdp.ConsumeIntInRange(0, 7)
    pdf = f"%PDF-1.{version}\n".encode()
    pdf += fdp.ConsumeBytes(min(8192, fdp.remaining_bytes()))
    if b"%%EOF" not in pdf:
        pdf += b"\n%%EOF\n"
    return pdf[:10000]


def fuzz_watermarking(data: bytes):
    """Fuzz watermarking methods."""
    if len(data) < 32:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Create PDF
    pdf_bytes = make_pdf(fdp)
    pdf_path = common.make_temp_file()
    pdf_path.write_bytes(pdf_bytes)

    # Get method
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

        if not isinstance(result, (bytes, bytearray)):
            raise AssertionError("apply_watermark must return bytes")

        if not result.startswith(b"%PDF"):
            raise AssertionError("Watermarked PDF must start with %PDF")

        # Read watermark
        out_path = common.make_temp_file()
        out_path.write_bytes(result)

        try:
            wm.read_watermark(method, str(out_path), key)
        finally:
            out_path.unlink(missing_ok=True)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception:
        # Expected for malformed PDFs
        pass
    finally:
        pdf_path.unlink(missing_ok=True)


def main():
    atheris.Setup(sys.argv, fuzz_watermarking)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
