import pymupdf as fitz  # PyMuPDF
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, create_string_object, DictionaryObject, StreamObject
import os
import tempfile
from io import BytesIO
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

class StructuralOverlay(WatermarkingMethod):

    @staticmethod
    def get_usage() -> str:
        return (
            "Toy method that overlays a visible watermark as well as"
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
                fontsize=40,
                rotate=45,
                color=(0.6, 0.6, 0.6),
                overlay=True,
                render_mode=3  # stroke + fill
            )

        output_stream = BytesIO()
        doc.save(output_stream)
        doc.close()
        output_stream.seek(0)
        return output_stream.read()
    
    @staticmethod
    def structural_watermark(pdf_bytes: bytes, watermark_data: str) -> bytes:
        """
        Adds a hidden structural watermark to the PDF (in-memory).
        Embeds hidden data in each page's dictionary.
        Returns the updated PDF as bytes.
        """
        input_stream = BytesIO(pdf_bytes)
        reader = PdfReader(input_stream)
        writer = PdfWriter()

        #Each page is watermarked. Stripping one page won't be enough to
        #remove the watermark
        for page in reader.pages:
            # Create a fake XObject (unused)
            dummy_stream = StreamObject()
            dummy_stream._data = b''  # empty stream
            dummy_stream.update({
                NameObject("/Type"): NameObject("/XObject"),
                NameObject("/Subtype"): NameObject("/Image"),
                NameObject("/Width"): 1,
                NameObject("/Height"): 1,
                NameObject("/ColorSpace"): NameObject("/DeviceGray"),
                NameObject("/BitsPerComponent"): 1,
                NameObject("/Filter"): NameObject("/FlateDecode"),
                NameObject("/Watermark"): create_string_object(watermark_data)
            })

            # Add to page's XObject dictionary
            if "/Resources" not in page:
                page[NameObject("/Resources")] = DictionaryObject()
            resources = page["/Resources"]

            if "/XObject" not in resources:
                resources[NameObject("/XObject")] = DictionaryObject()
            xobjects = resources["/XObject"]

            #Using an incospicuous name to try and blend in the secret better
            xobjects[NameObject("/Xf123")] = dummy_stream

            writer.add_page(page)

        output_stream = BytesIO()
        writer.write(output_stream)
        output_stream.seek(0)
        return output_stream.read()
    
    @staticmethod
    def get_fernet_from_key(key: str) -> Fernet:
        #fixed_salt = b'my-fixed-salt-1234'  # 16 bytes is reasonable, but must remain constant
        fixed_salt = b'try-and-break-me!!'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=fixed_salt,
            iterations=200_000,
        )
        fernet_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return Fernet(fernet_key)

    
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        
        data = load_pdf_bytes(pdf)
        #Add a visible watermark. This might confuse the attackers,
        #suggesting that the only watermark is the visible watermark.
        #It also works as a deterrent against document diffusion.
        visibly_watermarked = self.visible_watermark(data, "CONFIDENTIAL")

        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")
        
        #Add the "real" watermark by embedding the secret into
        #the PDF structure.
        f = self.get_fernet_from_key(key)
        watermark = f.encrypt(secret.encode())
        fully_watermarked = self.structural_watermark(visibly_watermarked, watermark)

        return fully_watermarked
    

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        pdf_bytes = load_pdf_bytes(pdf)
        reader = PdfReader(BytesIO(pdf_bytes))
        extracted_data = []

        #Cycle through each page in order to find the watermark
        for page in reader.pages:
            xobjects = page.get("/Resources", {}).get("/XObject", {})
            for xobj in xobjects.items():
                #Stop at first occurrence. All of them are the same.
                if isinstance(xobj, dict) and "/Watermark" in xobj:
                    extracted_data.append(str(xobj["/Watermark"]))
                    break
            else:
                extracted_data.append(None)

        for item in extracted_data:
            if item:
                f = self.get_fernet_from_key(key)
                watermark = f.decrypt(item).decode()
                return watermark
        raise SecretNotFoundError("No watermark found.")
    
    
    