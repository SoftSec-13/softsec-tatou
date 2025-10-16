"""Input builders for fuzzing."""

from .auth import build_auth_header, build_fuzzed_auth
from .rest_builders import (
    build_create_user,
    build_create_watermark,
    build_delete_document,
    build_login,
    build_read_watermark,
    build_upload_document,
)

__all__ = [
    "build_auth_header",
    "build_fuzzed_auth",
    "build_create_user",
    "build_login",
    "build_upload_document",
    "build_create_watermark",
    "build_read_watermark",
    "build_delete_document",
]
