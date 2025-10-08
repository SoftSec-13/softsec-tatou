#!/usr/bin/env python3
"""Stateful fuzzer - Tests multi-step workflows and IDOR vulnerabilities.

This fuzzer tests sequences of API calls including:
- User lifecycle: create → login → upload → access
- IDOR (Insecure Direct Object Reference) detection
- Watermark workflows
- Session management
"""

from __future__ import annotations

import io
import logging
import secrets
import sys

import atheris

with atheris.instrument_imports():
    from flask.testing import FlaskClient
    from utils import cleanup_storage, get_app

logger = logging.getLogger(__name__)


def _create_user_and_auth(
    client: FlaskClient, email: str, password: str, login: str
) -> str | None:
    """Create a user (ignoring existing ones) and return a Bearer token."""
    resp = client.post(
        "/api/create-user",
        json={"email": email, "password": password, "login": login},
    )
    if resp.status_code not in {200, 201, 409}:
        return None

    login_resp = client.post("/api/login", json={"email": email, "password": password})
    if login_resp.status_code != 200:
        return None
    token = (login_resp.get_json(silent=True) or {}).get("token")
    if not token:
        return None
    return f"Bearer {token}"


def fuzz_user_lifecycle(fdp: atheris.FuzzedDataProvider) -> None:
    """Test create user → login → upload → access flow.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness
    """
    app = get_app()

    # Generate test data
    user1_email = f"user1_{fdp.ConsumeIntInRange(0, 999999)}@fuzz.test"
    user1_password = fdp.ConsumeUnicodeNoSurrogates(32) or secrets.token_urlsafe(16)
    user1_login = user1_email.split("@")[0]

    try:
        with app.test_client() as client:
            auth1 = _create_user_and_auth(
                client, user1_email, user1_password, user1_login
            )
            if not auth1:
                return

            # 3. Upload document as user1
            filename = fdp.ConsumeUnicodeNoSurrogates(32) or "test.pdf"
            content = b"%PDF-1.7\ntest content\n%%EOF\n"

            resp3 = client.post(
                "/api/upload-document",
                headers={"Authorization": auth1},
                data={"file": (io.BytesIO(content), filename)},
                content_type="multipart/form-data",
            )

            if resp3.status_code not in {200, 201}:
                return

            doc_id = (resp3.get_json(silent=True) or {}).get("id")
            if not doc_id:
                return

            # 4. IDOR Test: Create second user and try to access first user's document
            user2_email = f"user2_{fdp.ConsumeIntInRange(0, 999)}@fuzz.test"
            user2_password = secrets.token_urlsafe(16)
            user2_login = user2_email.split("@")[0]

            auth2 = _create_user_and_auth(
                client, user2_email, user2_password, user2_login
            )
            if not auth2:
                return

            # Try to access user1's document as user2 (IDOR test)
            resp6 = client.get(
                "/api/get-document",
                headers={"Authorization": auth2},
                query_string={"id": doc_id},
            )

            # IDOR vulnerability if user2 can access user1's document
            if resp6.status_code == 200:
                # Check if actual document content is returned
                if b"%PDF" in resp6.data or "filename" in resp6.get_data(as_text=True):
                    raise AssertionError(
                        f"IDOR: User 2 can access User 1's document (id={doc_id})"
                    )

            # Also test list-documents endpoint
            resp7 = client.get("/api/list-documents", headers={"Authorization": auth2})

            data = resp7.get_json(silent=True) or {}
            if resp7.status_code == 200 and data:
                # Check if user2 can see user1's documents
                docs = data.get("documents", [])
                for doc in docs:
                    if doc.get("id") == doc_id:
                        raise AssertionError(
                            "IDOR: User 2 can list User 1's document "
                            "in /api/list-documents"
                        )

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug("Stateful lifecycle fuzz failed: %s", exc, exc_info=True)
    finally:
        cleanup_storage()


def fuzz_watermark_workflow(fdp: atheris.FuzzedDataProvider) -> None:
    """Test upload → watermark → read watermark flow.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness
    """
    app = get_app()

    user_email = f"wm_user_{fdp.ConsumeIntInRange(0, 999999)}@fuzz.test"
    user_password = secrets.token_urlsafe(16)
    user_login = user_email.split("@")[0]

    try:
        with app.test_client() as client:
            auth = _create_user_and_auth(client, user_email, user_password, user_login)
            if not auth:
                return

            # Upload document
            content = b"%PDF-1.7\ntest\n%%EOF\n"
            resp = client.post(
                "/api/upload-document",
                headers={"Authorization": auth},
                data={"file": (io.BytesIO(content), "test.pdf")},
                content_type="multipart/form-data",
            )

            if resp.status_code not in {200, 201}:
                return

            doc_id = (resp.get_json(silent=True) or {}).get("id")
            if not doc_id:
                return

            # Create watermark with fuzzed parameters
            secret = fdp.ConsumeUnicodeNoSurrogates(64)
            key = fdp.ConsumeUnicodeNoSurrogates(64)
            method = fdp.ConsumeUnicodeNoSurrogates(32)
            intended_for = fdp.ConsumeUnicodeNoSurrogates(64)

            resp = client.post(
                "/api/create-watermark",
                headers={"Authorization": auth},
                json={
                    "documentid": doc_id,
                    "secret": secret,
                    "key": key,
                    "method": method,
                    "intended_for": intended_for,
                },
            )

            if resp.status_code not in {200, 201, 400, 404}:
                raise AssertionError(f"Unexpected watermark status: {resp.status_code}")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug("Watermark workflow fuzz failed: %s", exc, exc_info=True)
    finally:
        cleanup_storage()


def fuzz_session_management(fdp: atheris.FuzzedDataProvider) -> None:
    """Test session handling edge cases.

    Args:
        fdp: Atheris FuzzedDataProvider for randomness
    """
    app = get_app()

    email = f"session_{fdp.ConsumeIntInRange(0, 999999)}@fuzz.test"
    password = secrets.token_urlsafe(16)

    try:
        with app.test_client() as client:
            auth = _create_user_and_auth(client, email, password, email.split("@")[0])
            if not auth:
                return

            # Test token reuse
            for _ in range(3):
                resp = client.get(
                    "/api/list-documents", headers={"Authorization": auth}
                )
                if resp.status_code not in {200, 401}:
                    raise AssertionError(
                        f"Unexpected status on token reuse: {resp.status_code}"
                    )

            # Test malformed token variations
            token_value = auth.split(" ", 1)[1]
            malformed_tokens = [
                token_value + "x",  # Slightly modified
                token_value[:-1],  # Truncated
                token_value[::-1],  # Reversed
                token_value.upper(),  # Case changed
                "",  # Empty
            ]

            for bad_token in malformed_tokens:
                resp = client.get(
                    "/api/list-documents",
                    headers={"Authorization": f"Bearer {bad_token}"},
                )
                # Should reject invalid tokens
                if resp.status_code == 200:
                    raise AssertionError(
                        f"Accepted malformed token: {bad_token[:20]}..."
                    )

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug("Session management fuzz failed: %s", exc, exc_info=True)
    finally:
        cleanup_storage()


def fuzz_one_input(data: bytes) -> None:
    """Main stateful fuzzing entry point.

    Args:
        data: Raw bytes from fuzzer
    """
    if len(data) < 16:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Pick fuzzing strategy
    strategy = fdp.ConsumeIntInRange(0, 2)

    if strategy == 0:
        fuzz_user_lifecycle(fdp)
    elif strategy == 1:
        fuzz_watermark_workflow(fdp)
    else:
        fuzz_session_management(fdp)


def main() -> None:
    """Entry point for fuzzer."""
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
