"""Security vulnerability detection for fuzzing responses.

This module contains comprehensive checks for various vulnerability classes
including SQL injection, XSS, SSRF, command injection, and more.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from werkzeug.wrappers import Response


# Vulnerability patterns organized by category
SQL_PATTERNS = [
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

XSS_PATTERNS = ["<script>", "javascript:", "onerror=", "onload="]

CMD_PATTERNS = ["/bin/sh", "/bin/bash", "sh -c", "cmd.exe", "; ls"]

SSRF_PATTERNS = ["localhost", "127.0.0.1", "169.254.169.254"]

DESER_PATTERNS = ["pickle", "dill", "yaml.load", "__reduce__"]

PATH_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    "root:x:",
    "/var/",
    "/proc/",
    "c:\\windows",
    "system32",
]

JWT_PATTERNS = ["alg.*none", '"alg":"none"', '"alg": "none"']

XXE_PATTERNS = ["<!entity", "<!doctype", 'system "file://', "<!element"]

SSTI_PATTERNS = ["{{", "{%", "${", "<%"]

NOSQL_PATTERNS = ["$where", "$ne", "$gt", "$regex", "undefined is not a function"]

SENSITIVE_EXTS = [".env", ".config", ".bak", ".old", ".key", ".pem", "id_rsa"]

# Endpoints that don't require authentication
PUBLIC_ENDPOINTS = ["/healthz", "/api/get-watermarking-methods"]


def check_security_vulnerabilities(resp: Response, endpoint: str) -> None:
    """Check response for security vulnerabilities.

    This function performs comprehensive security checks on HTTP responses,
    detecting various vulnerability classes through pattern matching and
    response analysis.

    Args:
        resp: The HTTP response object to check
        endpoint: The API endpoint that was called

    Raises:
        AssertionError: If a security vulnerability is detected

    Vulnerability Classes Detected:
        - SQL injection (error leakage)
        - Cross-Site Scripting (XSS)
        - Command injection
        - Server-Side Request Forgery (SSRF)
        - Unsafe deserialization
        - Path traversal
        - JWT vulnerabilities
        - XML External Entity (XXE)
        - Server-Side Template Injection (SSTI)
        - NoSQL injection
        - Information disclosure
        - Stack trace leakage
        - Authentication bypass
    """
    text = resp.get_data(as_text=True).lower()

    # SQL injection indicators
    for pattern in SQL_PATTERNS:
        if pattern in text:
            raise AssertionError(f"SQL vulnerability: {pattern} in {endpoint}")

    # XSS indicators (reflected in response)
    for pattern in XSS_PATTERNS:
        if pattern in text:
            raise AssertionError(f"XSS vulnerability: {pattern} in {endpoint}")

    # Command injection indicators
    for pattern in CMD_PATTERNS:
        if pattern in text:
            raise AssertionError(f"Command injection: {pattern} in {endpoint}")

    # SSRF indicators (internal URLs in response)
    for pattern in SSRF_PATTERNS:
        if pattern in text:
            raise AssertionError(f"SSRF vulnerability: {pattern} in {endpoint}")

    # AWS metadata endpoint specifically
    if "169.254.169.254" in text or "/latest/meta-data" in text:
        raise AssertionError(f"SSRF vulnerability: AWS metadata endpoint in {endpoint}")

    # Deserialization indicators
    for pattern in DESER_PATTERNS:
        if pattern in text:
            raise AssertionError(f"Unsafe deserialization: {pattern} in {endpoint}")

    # Path traversal success indicators
    for pattern in PATH_PATTERNS:
        if pattern in text:
            raise AssertionError(f"Path traversal: {pattern} in {endpoint}")

    # JWT vulnerabilities
    for pattern in JWT_PATTERNS:
        if pattern in text:
            raise AssertionError(f"JWT vulnerability: {pattern} in {endpoint}")

    # XXE (XML External Entity) indicators
    for pattern in XXE_PATTERNS:
        if pattern in text:
            raise AssertionError(f"XXE vulnerability: {pattern} in {endpoint}")

    # Server-Side Template Injection (SSTI)
    resp_headers = {k.lower(): v for k, v in resp.headers}
    if resp_headers.get("content-type", "").startswith("text/html"):
        request_data = (
            resp.request.get_data(as_text=True).lower() if resp.request.data else ""
        )
        for pattern in SSTI_PATTERNS:
            if pattern in text and pattern in request_data:
                raise AssertionError(f"SSTI reflection: {pattern} in {endpoint}")

    # NoSQL injection indicators
    for pattern in NOSQL_PATTERNS:
        if pattern in text:
            raise AssertionError(f"NoSQL injection: {pattern} in {endpoint}")

    # Information disclosure - sensitive file extensions
    for ext in SENSITIVE_EXTS:
        if ext in text:
            raise AssertionError(f"Sensitive file disclosure: {ext} in {endpoint}")

    # Stack trace leakage
    if resp.status_code >= 500:
        if any(p in text for p in ["file ", "line ", ".py", "traceback"]):
            raise AssertionError(f"Stack trace leaked in {endpoint}")

    # Check for authentication/authorization bypasses
    if endpoint not in PUBLIC_ENDPOINTS:
        if resp.status_code == 200:
            auth = resp.request.headers.get("Authorization", "")
            if not auth or not auth.startswith("Bearer "):
                raise AssertionError(f"Auth bypass possible on {endpoint}")
