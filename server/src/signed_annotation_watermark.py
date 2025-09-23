"""Tamper‑resistant watermark: encrypted embedded manifest + invisible annotation.

Summary:
- Encrypted JSON manifest embedded as ``WM-TATOU-SIGNED-v1.json``.
- Manifest lists secret + (xref, digest) pairs (SHA‑256) for selected objects.
- AES‑256‑GCM with PBKDF2-HMAC-SHA256 (120k iters) for confidentiality & integrity.
- Field name ``sha256`` kept for backward naming brevity though it stores SHA‑256.

Rationale: legitimate structures (embedded file, annotation) are harder to strip; object
digests detect naive copy or post‑embedding edits.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

try:  # PyMuPDF is required for all operations of this method
    import pymupdf  # type: ignore

    HAS_PYMUPDF = True
except Exception:  # pragma: no cover - environment check
    HAS_PYMUPDF = False


@dataclass
class _ObjectHash:
    xref: int
    sha256: str


class SignedAnnotationWatermark(WatermarkingMethod):
    """Embed encrypted manifest + invisible annotation and verify on extraction."""

    name = "signed-annots"

    # Constants
    _EMBED_NAME: Final[str] = "WM-TATOU-SIGNED-v1.json"
    _VERSION: Final[int] = 1
    _PBKDF2_ITER: Final[int] = 120_000
    _SALT_LEN: Final[int] = 16
    _OBJ_SAMPLE_LIMIT: Final[int] = 12

    @staticmethod
    def get_usage() -> str:
        return (
            "Tamper‑resistant watermark using encrypted embedded file"
            " + hidden annotation."
        )

    # ---------------------
    # Public API overrides
    # ---------------------
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        if not HAS_PYMUPDF:
            raise WatermarkingError("PyMuPDF is required for this watermark method")
        if not secret or not isinstance(secret, str):
            raise ValueError("Secret must be a non-empty string")
        if not key or not isinstance(key, str):
            raise ValueError("Key must be a non-empty string")

        original = load_pdf_bytes(pdf)
        try:
            doc = pymupdf.open(stream=original, filetype="pdf")
            new_doc = doc.write()  # normalize structure by reloading
            doc.close()
            original = load_pdf_bytes(new_doc)
            doc = pymupdf.open(stream=original, filetype="pdf")
        except Exception as exc:  # fallback: create new doc and append original as raw?
            raise WatermarkingError(f"Failed to open PDF: {exc}") from exc
        logger = logging.getLogger(__name__)
        try:
            # Some minimal test PDFs may have no page tree; enforce at least one page.
            if doc.page_count == 0:
                # Create a brand new document with a blank page instead
                logger.debug("Rebuilding minimal PDF to include a page")
                doc.close()
                doc = pymupdf.open()
                doc.new_page()
            watermark_id = str(uuid.uuid4())
            id_hint = watermark_id[:8]
            self._add_invisible_annotation(doc, f"WM:{id_hint}")
            obj_hashes = self._select_and_hash_objects(doc)
            salt = secrets.token_bytes(self._SALT_LEN)
            nonce = secrets.token_bytes(12)
            derived_key = self._derive_key(key, salt)
            plaintext = {
                "v": self._VERSION,
                "id": watermark_id,
                "secret": secret,
                "objs": [oh.__dict__ for oh in obj_hashes],
                "secret_len": len(secret),
            }
            pt_bytes = json.dumps(plaintext, separators=(",", ":")).encode("utf-8")
            ciphertext = AESGCM(derived_key).encrypt(nonce, pt_bytes, None)
            manifest = {
                "v": self._VERSION,
                "alg": "AES-256-GCM-PBKDF2",
                "iter": self._PBKDF2_ITER,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ciphertext).decode("ascii"),
                "id_hint": id_hint,
            }
            manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
            try:
                if (
                    hasattr(doc, "_embfile_names")
                    and self._EMBED_NAME in doc._embfile_names()
                ):
                    doc._embfile_del(self._EMBED_NAME)
            except Exception as exc:
                logger.debug("Cleanup of existing embedded file failed: %s", exc)
            try:
                if hasattr(doc, "_embfile_add"):
                    doc.embfile_add(
                        self._EMBED_NAME,
                        manifest_bytes,
                        filename=self._EMBED_NAME,
                        desc="Tatou signed watermark manifest v1",
                    )
            except Exception as exc:
                raise WatermarkingError(
                    f"Failed to attach watermark embedded file: {exc}"
                ) from exc
            return doc.write()
        finally:
            try:
                doc.close()
            except Exception as exc:
                logging.getLogger(__name__).debug("Closing document failed: %s", exc)

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        if not HAS_PYMUPDF:
            return False
        try:
            b = load_pdf_bytes(pdf)
            doc = pymupdf.open(stream=b, filetype="pdf")
        except Exception:
            return False
        finally:
            try:
                doc.close()
            except Exception as exc:
                logging.getLogger(__name__).debug("Closing document failed: %s", exc)
        return True

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        if not HAS_PYMUPDF:
            raise WatermarkingError("PyMuPDF is required for this watermark method")
        if not key or not isinstance(key, str):
            raise ValueError("Key must be a non-empty string")

        data = load_pdf_bytes(pdf)
        doc = pymupdf.open(stream=data, filetype="pdf")
        try:
            manifest_bytes = self._extract_manifest(doc)
            if manifest_bytes is None:
                raise SecretNotFoundError("Signed annotation watermark not found")

            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except Exception as exc:
                raise SecretNotFoundError("Malformed watermark manifest") from exc

            salt = base64.b64decode(manifest["salt"])
            nonce = base64.b64decode(manifest["nonce"])
            ct = base64.b64decode(manifest["ct"])
            iter_count = int(manifest.get("iter", self._PBKDF2_ITER))
            if iter_count <= 0 or iter_count > 2_000_000:  # sanity bounds
                raise WatermarkingError("Unreasonable PBKDF2 iteration count")

            key_bytes = self._derive_key(key, salt, iter_override=iter_count)
            aes = AESGCM(key_bytes)
            try:
                pt = aes.decrypt(nonce, ct, None)
            except Exception as exc:
                raise InvalidKeyError(
                    "Failed to authenticate watermark (key?)"
                ) from exc

            try:
                payload = json.loads(pt.decode("utf-8"))
            except Exception as exc:
                raise SecretNotFoundError("Corrupted decrypted payload") from exc

            # Validate structure
            if not (isinstance(payload, dict) and payload.get("secret")):
                raise SecretNotFoundError("Decrypted payload missing secret field")

            # Tamper check: recompute each hashed object
            self._verify_object_hashes(doc, payload.get("objs", []))

            return str(payload["secret"])
        finally:
            doc.close()

    # ---------------------
    # Internal helpers
    # ---------------------
    def _derive_key(
        self, password: str, salt: bytes, iter_override: int | None = None
    ) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iter_override or self._PBKDF2_ITER,
        )
        return kdf.derive(password.encode("utf-8"))

    def _select_and_hash_objects(self, doc: pymupdf.Document) -> list[_ObjectHash]:
        """Return hashes of a subset of objects after annotation insertion."""
        out: list[_ObjectHash] = []
        try:
            xref_len = doc.xref_length()
        except Exception:
            return out
        for xref in range(1, xref_len):
            if len(out) >= self._OBJ_SAMPLE_LIMIT:
                break
            try:
                obj_str = doc.xref_object(xref, compressed=False) or ""
            except Exception as exc:
                logging.getLogger(__name__).debug(
                    "Reading xref %s failed: %s", xref, exc
                )
                continue
            lower = obj_str.lower()
            if "/type /catalog" in lower or "/names" in lower:
                continue
            b = obj_str.encode("latin-1", "replace")
            if len(b.strip()) < 8:
                continue
            sha256 = self._sha256(b)
            out.append(_ObjectHash(xref=xref, sha256=sha256))
        return out

    def _add_invisible_annotation(self, doc: pymupdf.Document, text: str) -> None:
        logger = logging.getLogger(__name__)
        try:
            if doc.page_count == 0:
                doc.new_page()
            page = doc.load_page(0)
            annot = page.add_text_annot([2, 2], text)
            try:
                annot.set_flags(0b1111)
            except Exception as exc:
                logger.debug("Setting annotation flags failed: %s", exc)
            try:
                annot.set_opacity(0)
            except Exception as exc:
                logger.debug("Setting annotation opacity failed: %s", exc)
            try:
                annot.update()
            except Exception as exc:
                logger.debug("Annotation update failed: %s", exc)
        except Exception as exc:
            logger.debug("Adding invisible annotation failed: %s", exc)
        return None

    def _extract_manifest(self, doc: pymupdf.Document) -> bytes | None:
        # Primary: embedded file
        logger = logging.getLogger(__name__)
        try:
            if hasattr(doc, "_embfile_names"):
                names = doc.embfile_names()
                if self._EMBED_NAME in names:
                    file_bytes = doc.embfile_get(self._EMBED_NAME)
                    if isinstance(file_bytes, bytes | bytearray):
                        return bytes(file_bytes)
        except Exception as exc:
            logger.debug("Failed to extract embedded manifest: %s", exc)
        return None

    def _verify_object_hashes(self, doc: pymupdf.Document, entries: list[Any]) -> None:
        for e in entries:
            try:
                xref = int(e.get("xref"))
                expected = str(e.get("sha256"))
            except Exception:
                raise WatermarkingError("Malformed object hash entry") from None
            try:
                obj_str = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                raise WatermarkingError(
                    "Referenced object missing (tampered)"
                ) from None
            lower = obj_str.lower()
            if "/type /catalog" in lower or "/names" in lower:
                continue
            b = obj_str.encode("latin-1", "replace")
            actual = self._sha256(b)
            if actual != expected:
                raise WatermarkingError(
                    f"PDF appears tampered: object hash mismatch (xref {xref})"
                )

    @staticmethod
    def _sha256(b: bytes) -> str:
        h = hashes.Hash(hashes.SHA256())
        h.update(b)
        return h.finalize().hex()


__all__ = ["SignedAnnotationWatermark"]
