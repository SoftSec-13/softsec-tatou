import os
from pathlib import Path
from structural_and_overlay_watermark import StructuralOverlay
from watermarking_method import SecretNotFoundError

def load_pdf(path: str) -> bytes:
    """Loads a PDF file as bytes."""
    with open(path, "rb") as f:
        return f.read()

def save_pdf(path: str, data: bytes):
    """Saves PDF bytes to a file."""
    with open(path, "wb") as f:
        f.write(data)

def main():
    input_pdf_path = "input.pdf"         # ✅ PDF path
    output_pdf_path = "watermarked.pdf"  # ✅ Output file path
    secret = "this-is-a-secret" #pragma: allowlist secret
    key = "strong-password"

    if not Path(input_pdf_path).exists():
        print(f"❌ Input PDF not found: {input_pdf_path}")
        return

    print(f"✅ Loading PDF: {input_pdf_path}")
    original_pdf_bytes = load_pdf(input_pdf_path)

    method = StructuralOverlay()

    # Add watermark
    print("🔐 Embedding watermark...")
    watermarked_pdf = method.add_watermark(
        pdf=original_pdf_bytes,
        secret=secret,
        key=key,
        intended_for="John Smith"
    )

    # Save watermarked PDF
    save_pdf(output_pdf_path, watermarked_pdf)
    print(f"✅ Watermarked PDF saved to: {output_pdf_path}")

    # Try to read the watermark back
    print("🔍 Attempting to extract secret from watermarked PDF...")
    try:
        extracted = method.read_secret(pdf=watermarked_pdf, key=key)
        print(f"✅ Extracted secret: {extracted}")
    except SecretNotFoundError:
        print("❌ No watermark found in the PDF.")
    #except Exception as e:
        #print(f"❌ Error while extracting secret: {e}")

if __name__ == "__main__":
    main()
