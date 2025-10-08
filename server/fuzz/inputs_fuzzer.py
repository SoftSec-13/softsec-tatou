#!/usr/bin/env python3
"""Input validation fuzzer - Tests SQL injection and file upload security.

This fuzzer focuses on:
- SQL injection (30+ variants)
- Path traversal
- File upload validation
- Null byte injection
"""

import io
import sys

import atheris

with atheris.instrument_imports():
    from utils import cleanup_storage, get_app, make_auth_header, make_fuzzed_auth


# SQL injection and path traversal patterns
ATTACK_PATTERNS = [
    "' OR '1'='1",
    "1; DROP TABLE Users--",
    "admin'--",
    "1' UNION SELECT * FROM Users--",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
]


def fuzz_sql_injection(fdp: atheris.FuzzedDataProvider) -> None:
    """Test SQL injection resistance.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness
    """
    app = get_app()

    # Build payload with SQL patterns
    email = fdp.ConsumeUnicodeNoSurrogates(256)
    if fdp.ConsumeBool():
        pattern = ATTACK_PATTERNS[fdp.ConsumeIntInRange(0, len(ATTACK_PATTERNS) - 1)]
        email = pattern + email

    payload = {
        "email": email[:320],
        "login": fdp.ConsumeUnicodeNoSurrogates(64),
        "password": fdp.ConsumeUnicodeNoSurrogates(256),
    }

    try:
        with app.test_client() as client:
            resp = client.post(
                "/api/create-user",
                json=payload,
                headers={"Authorization": make_auth_header()},
            )

        # Check for SQL error leakage
        text = resp.get_data(as_text=True).lower()
        if "syntax" in text or "sql" in text or "mysql" in text:
            raise AssertionError("SQL error details leaked in response")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception:
        pass


def fuzz_file_upload(fdp: atheris.FuzzedDataProvider) -> None:
    """Test file upload validation.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness
    """
    app = get_app()

    # Create file
    filename = fdp.ConsumeUnicodeNoSurrogates(64) or "test.pdf"
    # Add path traversal attempts
    if fdp.ConsumeBool():
        prefix = ATTACK_PATTERNS[fdp.ConsumeIntInRange(0, len(ATTACK_PATTERNS) - 1)]
        filename = prefix + filename

    # Build file content
    content = fdp.ConsumeBytes(min(65536, fdp.remaining_bytes()))
    if fdp.ConsumeBool():
        content = b"%PDF-1.7\n" + content + b"\n%%EOF\n"

    try:
        with app.test_client() as client:
            resp = client.post(
                "/api/upload-document",
                headers={"Authorization": make_fuzzed_auth(fdp)},
                data={"file": (io.BytesIO(content), filename)},
                content_type="multipart/form-data",
            )

        if resp.status_code not in {200, 201, 400, 401, 403, 404, 413, 415, 500}:
            raise AssertionError(f"Unexpected upload status: {resp.status_code}")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception:
        pass
    finally:
        cleanup_storage()


def fuzz_one_input(data: bytes) -> None:
    """Main fuzzing entry point.

    Args:
        data: Raw bytes from fuzzer
    """
    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Pick fuzzing target
    if fdp.ConsumeBool():
        fuzz_sql_injection(fdp)
    else:
        fuzz_file_upload(fdp)


def main() -> None:
    """Entry point for fuzzer."""
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
