#!/usr/bin/env python3
"""Fuzz API endpoints and authentication."""

import sys

import atheris

with atheris.instrument_imports():
    import common


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


def check_security_issues(resp, endpoint: str) -> None:
    """Detect security vulnerabilities in response."""
    text = resp.get_data(as_text=True).lower()

    # SQL injection indicators
    sql_patterns = [
        "syntax error",
        "mysql",
        "mariadb",
        "sqlalchemy",
        "select * from",
        "table ",
        "column ",
        "sql",
        "query failed",
        "duplicate entry",
        "unknown column",
        "operand should contain",
    ]
    for pattern in sql_patterns:
        if pattern in text:
            raise AssertionError(f"SQL vulnerability: {pattern} in {endpoint}")

    # XSS indicators (reflected in response)
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]
    for pattern in xss_patterns:
        if pattern in text:
            raise AssertionError(f"XSS vulnerability: {pattern} in {endpoint}")

    # Command injection indicators
    cmd_patterns = ["/bin/sh", "/bin/bash", "sh -c", "cmd.exe", "; ls"]
    for pattern in cmd_patterns:
        if pattern in text:
            raise AssertionError(f"Command injection: {pattern} in {endpoint}")

    # SSRF indicators (internal URLs in response)
    ssrf_patterns = ["localhost", "127.0.0.1", "169.254.169.254"]
    for pattern in ssrf_patterns:
        if pattern in text:
            raise AssertionError(f"SSRF vulnerability: {pattern} in {endpoint}")

    # AWS metadata endpoint specifically
    if "169.254.169.254" in text or "/latest/meta-data" in text:
        raise AssertionError(f"SSRF vulnerability: AWS metadata endpoint in {endpoint}")

    # Deserialization indicators
    deser_patterns = ["pickle", "dill", "yaml.load", "__reduce__"]
    for pattern in deser_patterns:
        if pattern in text:
            raise AssertionError(f"Unsafe deserialization: {pattern} in {endpoint}")

    # Path traversal success indicators
    path_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "root:x:",
        "/var/",
        "/proc/",
        "c:\\windows",
        "system32",
    ]
    for pattern in path_patterns:
        if pattern in text:
            raise AssertionError(f"Path traversal: {pattern} in {endpoint}")

    # Stack trace leakage
    if resp.status_code >= 500:
        if any(p in text for p in ["file ", "line ", ".py", "traceback"]):
            raise AssertionError(f"Stack trace leaked in {endpoint}")

    # Check for authentication/authorization bypasses
    if endpoint not in ["/healthz", "/api/get-watermarking-methods"]:
        if resp.status_code == 200:
            auth = resp.request.headers.get("Authorization", "")
            if not auth or not auth.startswith("Bearer "):
                raise AssertionError(f"Auth bypass possible on {endpoint}")


def fuzz_api(data: bytes):
    """Fuzz API endpoints with various inputs."""
    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)
    app = common.get_app()

    # Pick endpoint
    endpoint, method = ENDPOINTS[fdp.ConsumeIntInRange(0, len(ENDPOINTS) - 1)]

    # Build payload
    payload = {
        "email": fdp.ConsumeUnicodeNoSurrogates(256),
        "password": fdp.ConsumeUnicodeNoSurrogates(256),
        "login": fdp.ConsumeUnicodeNoSurrogates(64),
        "method": fdp.ConsumeUnicodeNoSurrogates(32),
        "secret": fdp.ConsumeUnicodeNoSurrogates(128),
        "key": fdp.ConsumeUnicodeNoSurrogates(128),
        "intended_for": fdp.ConsumeUnicodeNoSurrogates(64),
        "id": fdp.ConsumeIntInRange(0, 999999),
        "documentid": fdp.ConsumeIntInRange(0, 999999),
    }

    headers = {"Authorization": common.make_fuzzed_auth(fdp)}

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

        # Check response
        if resp.status_code not in EXPECTED_STATUSES:
            raise AssertionError(
                f"Unexpected status {resp.status_code} for {method} {endpoint}"
            )

        # Check for security issues
        check_security_issues(resp, endpoint)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception:
        # Expected for malformed requests
        pass


def main():
    atheris.Setup(sys.argv, fuzz_api)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
