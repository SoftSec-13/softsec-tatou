"""Authentication token generation for fuzzing.

This module provides utilities for creating valid and malformed authentication
tokens to test authentication and authorization logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from itsdangerous import URLSafeTimedSerializer

if TYPE_CHECKING:
    from atheris import FuzzedDataProvider

from .app_setup import get_app


def make_auth_header(uid: int = 1, login: str = "fuzzer") -> str:
    """Create a valid Bearer authentication token.

    Args:
        uid: User ID for the token
        login: Username for the token

    Returns:
        Valid Bearer token string (format: "Bearer <token>")

    Example:
        >>> token = make_auth_header(uid=123, login="testuser")
        >>> token.startswith("Bearer ")
        True
    """
    app = get_app()
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps(
        {"uid": uid, "login": login, "email": f"{login}@fuzz.test"}
    )
    return f"Bearer {token}"


def make_fuzzed_auth(fdp: FuzzedDataProvider) -> str:
    """Create a fuzzed authentication header (valid or malformed).

    This function randomly generates either:
    1. A valid token with fuzzed user data
    2. A completely malformed token string

    Args:
        fdp: Atheris FuzzedDataProvider for randomness

    Returns:
        Authentication header string (may be valid or malformed)

    Example:
        >>> from atheris import FuzzedDataProvider
        >>> fdp = FuzzedDataProvider(b"test data")
        >>> auth = make_fuzzed_auth(fdp)
        >>> isinstance(auth, str)
        True
    """
    if fdp.ConsumeBool():
        # Generate valid token with fuzzed data
        uid = fdp.ConsumeIntInRange(1, 999999)
        login = fdp.ConsumeUnicodeNoSurrogates(32) or "fuzzer"
        return make_auth_header(uid, login[:64])

    # Return malformed token
    token = fdp.ConsumeUnicodeNoSurrogates(128)
    return f"Bearer {token}" if fdp.ConsumeBool() else token
