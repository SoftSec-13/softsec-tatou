"""PDF input models for fuzzing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PDFInput:
    """Model for PDF file inputs."""

    content: bytes
    filename: str = "fuzz.pdf"
    mimetype: str = "application/pdf"

    def __post_init__(self) -> None:
        """Validate and sanitize inputs."""
        # Ensure filename has .pdf extension
        if not self.filename.lower().endswith(".pdf"):
            self.filename += ".pdf"

        # Remove null bytes
        self.filename = self.filename.replace("\0", "")

        # Limit filename length
        if len(self.filename) > 200:
            self.filename = self.filename[:196] + ".pdf"

        # Ensure minimal PDF content
        if not self.content or len(self.content) < 10:
            self.content = b"%PDF-1.4\n%%EOF\n"

    @classmethod
    def minimal(cls) -> PDFInput:
        """Create minimal valid PDF."""
        return cls(content=b"%PDF-1.4\n%%EOF\n", filename="minimal.pdf")

    @classmethod
    def from_bytes(cls, data: bytes, filename: str | None = None) -> PDFInput:
        """Create from raw bytes."""
        return cls(
            content=data if data else b"%PDF-1.4\n%%EOF\n",
            filename=filename or "fuzz.pdf",
        )

    def mutate_content(self, mutation: bytes) -> PDFInput:
        """Create mutated copy with different content."""
        return PDFInput(
            content=mutation,
            filename=self.filename,
            mimetype=self.mimetype,
        )

    def mutate_filename(self, new_filename: str) -> PDFInput:
        """Create copy with different filename."""
        return PDFInput(
            content=self.content,
            filename=new_filename,
            mimetype=self.mimetype,
        )
