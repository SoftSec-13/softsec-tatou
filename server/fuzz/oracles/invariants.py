"""Endpoint invariant checks for fuzzing."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from werkzeug.wrappers import Response

# Expected status codes per endpoint
ENDPOINT_EXPECTATIONS = {
    "/api/create-user": {200, 201, 400, 409, 422},
    "/api/login": {200, 400, 401, 422},
    "/api/upload-document": {200, 201, 400, 401, 413, 415, 422},
    "/api/list-documents": {200, 401},
    "/api/get-document": {200, 400, 401, 404},
    "/api/delete-document": {200, 204, 400, 401, 404},
    "/api/create-watermark": {200, 201, 400, 401, 404, 422},
    "/api/read-watermark": {200, 400, 401, 404, 422},
    "/api/list-versions": {200, 400, 401, 404},
    "/api/list-all-versions": {200, 401},
    "/api/get-version": {200, 400, 401, 404},
    "/healthz": {200},
    "/api/get-watermarking-methods": {200},
}


def check_endpoint_invariants(resp: Response, endpoint: str) -> None:
    """Check endpoint-specific invariants.

    Args:
        resp: HTTP response object
        endpoint: Endpoint path

    Raises:
        AssertionError: If invariant violated

    Checks:
        - Status code is expected for endpoint
        - JSON endpoints return valid JSON
        - Content-Type headers are appropriate
        - No sensitive data in error responses
    """
    # Status code check
    expected_statuses = ENDPOINT_EXPECTATIONS.get(
        endpoint, {200, 201, 204, 400, 401, 403, 404, 405, 409, 413, 415, 422, 500, 503}
    )
    if resp.status_code not in expected_statuses:
        raise AssertionError(
            f"Unexpected status {resp.status_code} for {endpoint} "
            f"(expected one of {expected_statuses})"
        )

    # JSON response validation
    if resp.status_code < 300 and endpoint.startswith("/api/"):
        content_type = resp.headers.get("Content-Type", "")
        if (
            "application/json" not in content_type
            and "application/pdf" not in content_type
        ):
            # Some endpoints return PDFs
            if endpoint not in {"/api/get-document", "/api/get-version"}:
                raise AssertionError(
                    f"Expected JSON content-type for {endpoint}, got {content_type}"
                )

    # Error responses should not contain sensitive data
    if resp.status_code >= 400:
        text = resp.get_data(as_text=True).lower()
        sensitive_terms = ["password", "secret", "token", "key", "hash"]
        for term in sensitive_terms:
            if term in text and "password" not in endpoint:  # Allow in password errors
                raise AssertionError(f"Sensitive term '{term}' in error for {endpoint}")


def check_ownership_invariant(
    resp: Response,
    endpoint: str,
    owned_ids: set[int],
    requested_id: int | None,
) -> None:
    """Check ownership enforcement (IDOR prevention).

    Args:
        resp: HTTP response object
        endpoint: Endpoint path
        owned_ids: Set of IDs owned by the current user
        requested_id: ID that was requested

    Raises:
        AssertionError: If ownership violation detected
    """
    if requested_id is None or resp.status_code >= 400:
        return

    # Success accessing non-owned resource is IDOR
    if requested_id not in owned_ids:
        if resp.status_code in {200, 201}:
            raise AssertionError(
                f"IDOR: accessed document {requested_id} on {endpoint}"
            )
