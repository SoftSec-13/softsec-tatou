#!/usr/bin/env python3
"""API endpoint fuzzer - Tests authentication, authorization, and input validation.

This fuzzer targets Flask API endpoints with various attack patterns including:
- SQL injection
- XSS (Cross-Site Scripting)
- SSRF (Server-Side Request Forgery)
- JWT vulnerabilities
- NoSQL injection
- Type confusion
- Prototype pollution
- Authentication bypass
"""

import sys

import atheris

with atheris.instrument_imports():
    from utils import check_security_vulnerabilities, get_app, make_fuzzed_auth


# API endpoints to test
ENDPOINTS = [
    ("/api/create-user", "POST"),
    ("/api/login", "POST"),
    ("/api/upload-document", "POST"),
    ("/api/list-documents", "GET"),
    ("/api/get-document", "GET"),
    ("/api/delete-document", "DELETE"),
    ("/api/create-watermark", "POST"),
    ("/api/read-watermark", "POST"),
    ("/api/list-versions", "GET"),
    ("/api/get-watermarking-methods", "GET"),
    ("/healthz", "GET"),
]

EXPECTED_STATUSES = {200, 201, 400, 401, 403, 404, 405, 409, 413, 415, 422, 500, 503}


def build_fuzzed_payload(fdp: atheris.FuzzedDataProvider) -> dict:
    """Build payload using various fuzzing strategies.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness

    Returns:
        Fuzzed payload dictionary

    Strategies:
        0: Edge cases (empty, very long, boundary values)
        1: Type confusion (wrong types)
        2: Prototype pollution
        3: Nested objects/arrays
        4: Random fuzzing
    """
    strategy = fdp.ConsumeIntInRange(0, 4)

    if strategy == 0:
        # Edge cases: empty, very long, boundary values
        return {
            "email": ["", "a" * 1000, "a@b", None][fdp.ConsumeIntInRange(0, 3)],
            "password": ["", "x", "a" * 10000, None][fdp.ConsumeIntInRange(0, 3)],
            "login": ["", "a", "a" * 500][fdp.ConsumeIntInRange(0, 2)],
            "id": [-1, 0, 2147483647, -2147483648, 9223372036854775807][
                fdp.ConsumeIntInRange(0, 4)
            ],
            "documentid": [-999999, 0, 1, 999999, 2147483647][
                fdp.ConsumeIntInRange(0, 4)
            ],
        }
    elif strategy == 1:
        # Type confusion: wrong types
        return {
            "email": [None, [], {}, 123, True, 3.14][fdp.ConsumeIntInRange(0, 5)],
            "password": [None, [], {}, False][fdp.ConsumeIntInRange(0, 3)],
            "login": [None, 123, [], {}][fdp.ConsumeIntInRange(0, 3)],
            "id": ["not_a_number", None, [], "999999"][fdp.ConsumeIntInRange(0, 3)],
            "documentid": [None, "string", [], {}][fdp.ConsumeIntInRange(0, 3)],
        }
    elif strategy == 2:
        # Prototype pollution attempts
        return {
            "email": fdp.ConsumeUnicodeNoSurrogates(128),
            "password": fdp.ConsumeUnicodeNoSurrogates(128),
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}},
        }
    elif strategy == 3:
        # Nested objects and arrays
        return {
            "email": {"nested": fdp.ConsumeUnicodeNoSurrogates(64)},
            "password": [fdp.ConsumeUnicodeNoSurrogates(32) for _ in range(3)],
            "data": {"a": {"b": {"c": {"d": "deep"}}}},
        }
    else:
        # Random fuzzing (original approach)
        return {
            "email": fdp.ConsumeUnicodeNoSurrogates(256),
            "password": fdp.ConsumeUnicodeNoSurrogates(256),
            "login": fdp.ConsumeUnicodeNoSurrogates(64),
            "method": fdp.ConsumeUnicodeNoSurrogates(32),
            "secret": fdp.ConsumeUnicodeNoSurrogates(128),
            "key": fdp.ConsumeUnicodeNoSurrogates(128),
            "intended_for": fdp.ConsumeUnicodeNoSurrogates(64),
            "id": fdp.ConsumeIntInRange(-999999, 999999),
            "documentid": fdp.ConsumeIntInRange(-999999, 999999),
        }


def fuzz_one_input(data: bytes) -> None:
    """Fuzz API endpoints with various inputs.

    Args:
        data: Raw bytes from fuzzer (converted to structured data)
    """
    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)
    app = get_app()

    # Pick endpoint
    endpoint, method = ENDPOINTS[fdp.ConsumeIntInRange(0, len(ENDPOINTS) - 1)]

    # Build payload
    payload = build_fuzzed_payload(fdp)

    # Add random extra fields (pollution test)
    if fdp.ConsumeBool():
        payload[fdp.ConsumeUnicodeNoSurrogates(16) or "extra"] = (
            fdp.ConsumeUnicodeNoSurrogates(32)
        )

    headers = {"Authorization": make_fuzzed_auth(fdp)}

    # Fuzz headers
    if fdp.ConsumeBool():
        headers["Content-Type"] = fdp.PickValueInList(
            [
                "application/json",
                "text/plain",
                "application/xml",
                "multipart/form-data",
                "application/x-www-form-urlencoded",
                "a" * 100,
                "",
            ]
        )

    try:
        with app.test_client() as client:
            if method == "GET":
                resp = client.get(endpoint, headers=headers, query_string=payload)
            elif method == "POST":
                resp = client.post(endpoint, headers=headers, json=payload)
            elif method == "DELETE":
                resp = client.delete(endpoint, headers=headers, json=payload)
            else:
                return

        # Check response status
        if resp.status_code not in EXPECTED_STATUSES:
            raise AssertionError(
                f"Unexpected status {resp.status_code} for {method} {endpoint}"
            )

        # Check for security vulnerabilities
        check_security_vulnerabilities(resp, endpoint)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception:
        # Expected for malformed requests
        pass


def main() -> None:
    """Entry point for fuzzer."""
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
