import fitz  # PyMuPDF
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, create_string_object, DictionaryObject, StreamObject
import os
import tempfile
from io import BytesIO

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
    
    def structural_watermark(pdf_bytes: bytes, hidden_data: str) -> bytes:
        """
        Adds a hidden structural watermark to the PDF (in-memory).
        Embeds hidden data in each page's dictionary.
        Returns the updated PDF as bytes.
        """
        input_stream = BytesIO(pdf_bytes)
        reader = PdfReader(input_stream)
        writer = PdfWriter()

        for page in reader.pages:
            #TODO: change watermark location, this one is too obvious
            hidden_tag = DictionaryObject()
            hidden_tag.update({
                NameObject("/HiddenWatermark"): create_string_object(hidden_data)
            })
            page[NameObject("/Watermark")] = hidden_tag
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
        fully_watermarked = self.structural_watermark(visibly_watermarked, secret)

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

        for page in reader.pages:
            # Check for our custom structural watermark
            #TODO: change watermark location, this one is too obvious
            watermark_obj = page.get("/Watermark")
            if watermark_obj and "/HiddenWatermark" in watermark_obj:
                hidden = watermark_obj["/HiddenWatermark"]
                # Extract string, decode if necessary
                extracted_data.append(str(hidden))
            else:
                extracted_data.append(None)  # No watermark found on this page

        return str(extracted_data)
    