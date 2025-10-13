"""REST API request builders for fuzzing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from models import (
    CreateUserPayload,
    CreateWatermarkPayload,
    DeleteDocumentPayload,
    LoginPayload,
    PDFInput,
    ReadWatermarkPayload,
    UploadDocumentPayload,
)

if TYPE_CHECKING:
    import atheris


def build_create_user(
    fdp: atheris.FuzzedDataProvider | None = None,
) -> CreateUserPayload:
    """Build create-user payload with optional fuzzing.

    Args:
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        CreateUserPayload instance
    """
    if fdp is None or not fdp.remaining_bytes():
        return CreateUserPayload.valid()

    email = fdp.ConsumeUnicodeNoSurrogates(320) or "fuzz@test.com"
    password = fdp.ConsumeUnicodeNoSurrogates(256) or "FuzzPass123!"
    login = fdp.ConsumeUnicodeNoSurrogates(64) if fdp.ConsumeBool() else None

    return CreateUserPayload(email=email, password=password, login=login)


def build_login(fdp: atheris.FuzzedDataProvider | None = None) -> LoginPayload:
    """Build login payload with optional fuzzing.

    Args:
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        LoginPayload instance
    """
    if fdp is None or not fdp.remaining_bytes():
        return LoginPayload.valid()

    email = fdp.ConsumeUnicodeNoSurrogates(320) or "fuzz@test.com"
    password = fdp.ConsumeUnicodeNoSurrogates(256) or "FuzzPass123!"

    return LoginPayload(email=email, password=password)


def build_upload_document(
    pdf_input: PDFInput | None = None,
    fdp: atheris.FuzzedDataProvider | None = None,
) -> tuple[PDFInput, UploadDocumentPayload]:
    """Build upload-document request with PDF and payload.

    Args:
        pdf_input: Optional PDF input (defaults to minimal PDF)
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        Tuple of (PDFInput, UploadDocumentPayload)
    """
    if pdf_input is None:
        pdf_input = PDFInput.minimal()

    if fdp is None or not fdp.remaining_bytes():
        return (pdf_input, UploadDocumentPayload.valid())

    intended_for = fdp.ConsumeUnicodeNoSurrogates(320) or "recipient@test.com"
    method = fdp.ConsumeUnicodeNoSurrogates(64) or "basic"

    # Optional extra fields for fuzzing
    extras: dict[str, Any] = {}
    if fdp.remaining_bytes() and fdp.ConsumeBool():
        extras["extra_field"] = fdp.ConsumeUnicodeNoSurrogates(128)

    payload = UploadDocumentPayload(
        intended_for=intended_for,
        method=method,
        extras=extras,
    )

    return (pdf_input, payload)


def build_create_watermark(
    documentid: int = 1,
    fdp: atheris.FuzzedDataProvider | None = None,
) -> CreateWatermarkPayload:
    """Build create-watermark payload with optional fuzzing.

    Args:
        documentid: Document ID to watermark
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        CreateWatermarkPayload instance
    """
    if fdp is None or not fdp.remaining_bytes():
        return CreateWatermarkPayload.valid(documentid=documentid)

    method = fdp.ConsumeUnicodeNoSurrogates(64) or "basic"
    intended_for = fdp.ConsumeUnicodeNoSurrogates(320) or "recipient@test.com"
    secret = fdp.ConsumeUnicodeNoSurrogates(256) or "test-secret"
    key = fdp.ConsumeUnicodeNoSurrogates(256) or "test-key"
    position = fdp.ConsumeUnicodeNoSurrogates(64) if fdp.ConsumeBool() else None

    return CreateWatermarkPayload(
        documentid=documentid,
        method=method,
        intended_for=intended_for,
        secret=secret,
        key=key,
        position=position,
    )


def build_read_watermark(
    documentid: int = 1,
    fdp: atheris.FuzzedDataProvider | None = None,
) -> ReadWatermarkPayload:
    """Build read-watermark payload with optional fuzzing.

    Args:
        documentid: Document ID to read watermark from
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        ReadWatermarkPayload instance
    """
    if fdp is None or not fdp.remaining_bytes():
        return ReadWatermarkPayload.valid(documentid=documentid)

    method = fdp.ConsumeUnicodeNoSurrogates(64) or "basic"
    key = fdp.ConsumeUnicodeNoSurrogates(256) or "test-key"

    return ReadWatermarkPayload(
        documentid=documentid,
        method=method,
        key=key,
    )


def build_delete_document(
    documentid: int = 1,
    fdp: atheris.FuzzedDataProvider | None = None,
) -> DeleteDocumentPayload:
    """Build delete-document payload with optional fuzzing.

    Args:
        documentid: Document ID to delete
        fdp: Optional FuzzedDataProvider for mutations

    Returns:
        DeleteDocumentPayload instance
    """
    if fdp is None or not fdp.remaining_bytes():
        return DeleteDocumentPayload.valid(documentid=documentid)

    # Optionally fuzz document ID
    if fdp.ConsumeBool():
        documentid = fdp.ConsumeIntInRange(-1000, 1000000)

    return DeleteDocumentPayload(documentid=documentid)
