"""REST API payload models for fuzzing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CreateUserPayload:
    """Payload for /api/create-user endpoint."""

    email: str
    password: str
    login: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        payload: dict[str, Any] = {"email": self.email, "password": self.password}
        if self.login is not None:
            payload["login"] = self.login
        return payload

    @classmethod
    def valid(cls) -> CreateUserPayload:
        """Create valid payload with defaults."""
        return cls(email="fuzz@test.com", password="FuzzPass123!", login="fuzzuser")


@dataclass
class LoginPayload:
    """Payload for /api/login endpoint."""

    email: str
    password: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {"email": self.email, "password": self.password}

    @classmethod
    def valid(cls) -> LoginPayload:
        """Create valid payload with defaults."""
        return cls(email="fuzz@test.com", password="FuzzPass123!")


@dataclass
class UploadDocumentPayload:
    """Payload for /api/upload-document endpoint."""

    intended_for: str = "recipient@test.com"
    method: str = "basic"
    extras: dict[str, Any] = field(default_factory=dict)

    def to_form_data(self) -> dict[str, Any]:
        """Convert to form data dictionary."""
        data = {
            "intended_for": self.intended_for,
            "method": self.method,
        }
        data.update(self.extras)
        return data

    @classmethod
    def valid(cls) -> UploadDocumentPayload:
        """Create valid payload with defaults."""
        return cls(intended_for="recipient@test.com", method="basic")


@dataclass
class CreateWatermarkPayload:
    """Payload for /api/create-watermark endpoint."""

    documentid: int
    method: str
    intended_for: str
    secret: str
    key: str
    position: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        payload: dict[str, Any] = {
            "documentid": self.documentid,
            "method": self.method,
            "intended_for": self.intended_for,
            "secret": self.secret,
            "key": self.key,
        }
        if self.position is not None:
            payload["position"] = self.position
        return payload

    @classmethod
    def valid(cls, documentid: int = 1) -> CreateWatermarkPayload:
        """Create valid payload with defaults."""
        return cls(
            documentid=documentid,
            method="basic",
            intended_for="recipient@test.com",
            secret="test-secret",
            key="test-key",
        )


@dataclass
class ReadWatermarkPayload:
    """Payload for /api/read-watermark endpoint."""

    documentid: int
    method: str
    key: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "documentid": self.documentid,
            "method": self.method,
            "key": self.key,
        }

    @classmethod
    def valid(cls, documentid: int = 1) -> ReadWatermarkPayload:
        """Create valid payload with defaults."""
        return cls(documentid=documentid, method="basic", key="test-key")


@dataclass
class DeleteDocumentPayload:
    """Payload for /api/delete-document endpoint."""

    documentid: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {"documentid": self.documentid}

    @classmethod
    def valid(cls, documentid: int = 1) -> DeleteDocumentPayload:
        """Create valid payload with defaults."""
        return cls(documentid=documentid)
