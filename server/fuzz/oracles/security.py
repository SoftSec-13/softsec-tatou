"""Security vulnerability detection for HTTP responses."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from werkzeug.wrappers import Response

# Vulnerability patterns
SQL_PATTERNS = [
    "syntax error",
    "mysql",
    "mariadb",
    "sqlalchemy",
    "select * from",
    "table ",
    "column ",
    " sql",
    "query failed",
    "duplicate entry",
    "unknown column",
    "operand should contain",
    "operationalerror",
    "integrityerror",
    "programmeerror",
]

XSS_PATTERNS = ["<script>", "javascript:", "onerror=", "onload=", "onclick="]

CMD_PATTERNS = ["/bin/sh", "/bin/bash", "sh -c", "cmd.exe", "; ls", "| cat"]

SSRF_PATTERNS = ["localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0"]

PATH_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    "root:x:",
    "/var/log",
    "/proc/",
    "c:\\windows",
    "system32",
]

SENSITIVE_EXTS = [".env", ".config", ".bak", ".old", ".key", ".pem", "id_rsa"]

PUBLIC_ENDPOINTS = ["/healthz", "/api/get-watermarking-methods"]

# Performance thresholds (configurable via env)
# Default threshold for most endpoints
MAX_RESPONSE_TIME_MS = 1000

# Per-endpoint thresholds for operations that are legitimately slower
# PDF/crypto operations can take longer due to parsing and cryptographic operations
ENDPOINT_LATENCY_THRESHOLDS = {
    "/api/create-watermark": 2000,  # Watermarking + PDF modification
    "/api/read-watermark": 2000,  # Watermark extraction + crypto validation
    "/api/upload-document": 1500,  # PDF upload + validation
    "/api/get-document": 800,  # PDF retrieval
    "/api/get-version": 800,  # Versioned PDF retrieval
}


def check_security_vulnerabilities(
    resp: Response,
    endpoint: str,
    start_time: float | None = None,
) -> None:
    """Check HTTP response for security vulnerabilities.

    Args:
        resp: HTTP response object
        endpoint: Endpoint path template
        start_time: Optional request start time for latency check

    Raises:
        AssertionError: If vulnerability detected

    Detects:
        - SQL injection (error leakage, broader DB error patterns)
        - XSS (reflected content)
        - Command injection
        - SSRF (internal URLs)
        - Path traversal
        - Information disclosure
        - Stack trace leakage
        - Authentication bypass
        - Slow responses (DoS indicators)
    """
    text = resp.get_data(as_text=True).lower()

    # SQL injection - enhanced patterns
    for pattern in SQL_PATTERNS:
        if pattern in text:
            raise AssertionError(f"SQL vulnerability: {pattern} in {endpoint}")

    # XSS
    for pattern in XSS_PATTERNS:
        if pattern in text:
            raise AssertionError(f"XSS vulnerability: {pattern} in {endpoint}")

    # Command injection
    for pattern in CMD_PATTERNS:
        if pattern in text:
            raise AssertionError(f"Command injection: {pattern} in {endpoint}")

    # SSRF
    for pattern in SSRF_PATTERNS:
        if pattern in text:
            raise AssertionError(f"SSRF vulnerability: {pattern} in {endpoint}")

    # AWS metadata endpoint
    if "169.254.169.254" in text or "/latest/meta-data" in text:
        raise AssertionError(f"SSRF: AWS metadata endpoint in {endpoint}")

    # Path traversal success
    for pattern in PATH_PATTERNS:
        if pattern in text:
            raise AssertionError(f"Path traversal: {pattern} in {endpoint}")

    # Sensitive file disclosure
    for ext in SENSITIVE_EXTS:
        if ext in text:
            raise AssertionError(f"Sensitive file: {ext} in {endpoint}")

    # Stack trace leakage
    if resp.status_code >= 500:
        if any(p in text for p in ["file ", "line ", ".py", "traceback"]):
            raise AssertionError(f"Stack trace leaked in {endpoint}")

    # Authentication bypass check
    if endpoint not in PUBLIC_ENDPOINTS and resp.status_code == 200:
        auth = resp.request.headers.get("Authorization", "")
        if not auth or not auth.startswith("Bearer "):
            raise AssertionError(f"Auth bypass possible on {endpoint}")

    # Latency check (DoS indicator) with per-endpoint thresholds
    if start_time is not None:
        elapsed_ms = (time.time() - start_time) * 1000
        # Use endpoint-specific threshold if available, otherwise use default
        threshold_ms = ENDPOINT_LATENCY_THRESHOLDS.get(endpoint, MAX_RESPONSE_TIME_MS)
        if elapsed_ms > threshold_ms:
            raise AssertionError(
                f"Slow response ({elapsed_ms:.1f}ms > {threshold_ms}ms) on {endpoint}"
            )

    # Response size check (potential DoS)
    content_length = len(resp.get_data())
    if content_length > 10_000_000:  # 10MB
        raise AssertionError(
            f"Excessive response size ({content_length} bytes) on {endpoint}"
        )
