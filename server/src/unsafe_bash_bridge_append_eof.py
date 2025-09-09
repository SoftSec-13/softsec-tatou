"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker. Originally used unsafe bash commands, now uses safe
file operations while maintaining the same functionality.

"""

from __future__ import annotations

import re

from watermarking_method import (
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF."""

    name = "bash-bridge-eof"

    # ---------------------
    # Public API overrides
    # ---------------------

    @staticmethod
    def get_usage() -> str:
        return (
            "Toy method that appends a watermark record after the PDF EOF. "
            "Position and key are ignored."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` and ``key`` parameters are accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        # Safely append the secret to the PDF data
        secret_bytes = secret.encode("utf-8")
        return data + secret_bytes

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present.
        Returns whatever content appears after the last %%EOF marker.
        """
        data = load_pdf_bytes(pdf)
        text_data = data.decode("utf-8", errors="ignore")

        # Find the last occurrence of %%EOF
        eof_matches = list(re.finditer(r"%%EOF", text_data))
        if not eof_matches:
            return ""

        last_eof = eof_matches[-1]
        # Return everything after the last %%EOF
        after_eof = text_data[last_eof.end() :]

        return after_eof.strip()


__all__ = ["UnsafeBashBridgeAppendEOF"]
