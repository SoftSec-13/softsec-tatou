import base64
from io import BytesIO

import pymupdf as fitz
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import (
    DictionaryObject,
    NameObject,
    create_string_object,
)

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)


class StructuralOverlay(WatermarkingMethod):
    name = "overlay-watermark"

    @staticmethod
    def get_usage() -> str:
        return (
            "Method that overlays a visible watermark as well as"
            "embedding a structural watermark. "
        )

    @staticmethod
    def visible_watermark(pdf_bytes: bytes, visible_watermark: str):
        """
        Applies a visible watermark to each page of a PDF (in-memory).
        Returns the updated PDF as bytes.
        """
        input_stream = BytesIO(pdf_bytes)
        doc = fitz.open(stream=input_stream, filetype="pdf")

        for page in doc:
            page.insert_text(
                (72, 72),  # Top-left corner (x, y)
                visible_watermark,
                fontsize=18,
                rotate=0,
                fill=(0.6, 0.6, 0.6),  # fill color (gray)
                color=(0, 0, 0),
                overlay=True,
                render_mode=2,  # stroke + fill
                fill_opacity=0.5,
                stroke_opacity=0.5,
            )

        output_stream = BytesIO()
        doc.save(output_stream)
        doc.close()
        output_stream.seek(0)
        return output_stream.read()

    @staticmethod
    def structural_watermark(pdf_bytes: bytes, hidden_data: str) -> bytes:
        """
        Adds a hidden structural watermark to the PDF (in-memory).
        Embeds hidden data in each page's dictionary.
        Returns the updated PDF as bytes.
        """
        input_stream = BytesIO(pdf_bytes)
        reader = PdfReader(input_stream)
        writer = PdfWriter()

        # Creating an incospicuous location to hide the watermark.
        # Adding in /PieceInfo (app. specific metadata)
        # Obfuscated name makes it less obvious than "/Watermark"
        obfuscated_key = NameObject("/XObjD5fA2e1")

        for page in reader.pages:
            piece_info = page.get("/PieceInfo") or DictionaryObject()
            piece_info.update({obfuscated_key: create_string_object(hidden_data)})
            page[NameObject("/PieceInfo")] = piece_info
            writer.add_page(page)

        output_stream = BytesIO()
        writer.write(output_stream)
        output_stream.seek(0)
        return output_stream.read()

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        intended_for: str | None = None,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        # Add a visible watermark. This might confuse the attackers,
        # suggesting that the only watermark is the visible watermark.
        # It also works as a deterrent against document diffusion.
        if not intended_for:
            raise ValueError("Missing recipient. (intended_for)")
        visibly_watermarked = self.visible_watermark(
            data, "Intended for: " + intended_for + "\nDo not disclose"
        )

        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        # Add the "real" watermark by embedding the secret into
        # the PDF structure.
        # Encrypt the secret for extra security
        derived_key = self.derive_fernet_key(key)
        fernet = Fernet(derived_key)
        encrypted_secret = fernet.encrypt(secret.encode()).decode()
        fully_watermarked = self.structural_watermark(
            visibly_watermarked, encrypted_secret
        )

        return fully_watermarked

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True

    @staticmethod
    def derive_fernet_key(password: str) -> bytes:
        """
        Derive a Fernet-compatible key from a string password using PBKDF2.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"try_and_break_me",
            iterations=200_000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        pdf_bytes = load_pdf_bytes(pdf)
        reader = PdfReader(BytesIO(pdf_bytes))
        extracted_data = []

        obfuscated_key = NameObject("/XObjD5fA2e1")

        for page in reader.pages:
            # Check for our custom structural watermark
            watermark_obj = page.get("/PieceInfo")
            if watermark_obj and obfuscated_key in watermark_obj:
                hidden = watermark_obj[obfuscated_key]
                # Extract string
                encrypted_str = str(hidden)

                # Try decryption, catch exceptions
                try:
                    derived_key = self.derive_fernet_key(key)
                    fernet = Fernet(derived_key)
                    decrypted = fernet.decrypt(encrypted_str.encode()).decode()
                    extracted_data.append(decrypted)
                except InvalidToken as e:
                    raise InvalidKeyError("Failed to decrypt watermark") from e
            else:
                extracted_data.append(None)  # No watermark found on this page

        return str(extracted_data)
