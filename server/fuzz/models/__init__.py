"""Data models for fuzzing inputs."""

from .pdf import PDFInput
from .rest import (
    CreateUserPayload,
    CreateWatermarkPayload,
    DeleteDocumentPayload,
    LoginPayload,
    ReadWatermarkPayload,
    UploadDocumentPayload,
)

__all__ = [
    "PDFInput",
    "CreateUserPayload",
    "LoginPayload",
    "UploadDocumentPayload",
    "CreateWatermarkPayload",
    "ReadWatermarkPayload",
    "DeleteDocumentPayload",
]
