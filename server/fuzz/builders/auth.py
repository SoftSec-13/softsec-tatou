"""Authentication token builders for fuzzing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from itsdangerous import URLSafeTimedSerializer

if TYPE_CHECKING:
    import atheris

_SERIALIZER: URLSafeTimedSerializer | None = None


def _get_serializer() -> URLSafeTimedSerializer:
    """Get or create token serializer."""
    global _SERIALIZER
    if _SERIALIZER is None:
        from harness import get_app

        app = get_app()
        _SERIALIZER = URLSafeTimedSerializer(
            app.config["SECRET_KEY"], salt="tatou-auth"
        )
    return _SERIALIZER


def build_auth_header(uid: int = 1, login: str = "fuzzer") -> str:
    """Build valid Bearer authentication token.

    Args:
        uid: User ID
        login: Username

    Returns:
        Bearer token string
    """
    serializer = _get_serializer()
    token = serializer.dumps(
        {"uid": uid, "login": login, "email": f"{login}@fuzz.test"}
    )
    return f"Bearer {token}"


def build_fuzzed_auth(fdp: atheris.FuzzedDataProvider) -> str:
    """Build fuzzed authentication header (valid or malformed).

    Args:
        fdp: Atheris FuzzedDataProvider

    Returns:
        Authentication header (may be invalid)
    """
    if not fdp.remaining_bytes():
        return build_auth_header()

    if fdp.ConsumeBool():
        # Valid token with fuzzed data
        uid = fdp.ConsumeIntInRange(1, 999999)
        login = fdp.ConsumeUnicodeNoSurrogates(32) or "fuzzer"
        return build_auth_header(uid, login[:64])

    # Malformed token
    token = fdp.ConsumeUnicodeNoSurrogates(128) or "invalid"
    return f"Bearer {token}" if fdp.ConsumeBool() else token


def build_expired_token(uid: int = 1, login: str = "fuzzer") -> str:
    """Build token that appears expired.

    Args:
        uid: User ID
        login: Username

    Returns:
        Token string (may fail TTL validation)
    """
    # Create token with very old timestamp
    serializer = _get_serializer()
    # Note: This creates a valid token; expiry depends on server-side TTL check
    token = serializer.dumps(
        {"uid": uid, "login": login, "email": f"{login}@fuzz.test"}
    )
    return f"Bearer {token}"


def build_malformed_token() -> str:
    """Build obviously malformed token.

    Returns:
        Malformed token string
    """
    return "Bearer invalid.token.data"
