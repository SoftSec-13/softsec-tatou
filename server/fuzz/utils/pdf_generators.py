"""PDF generation strategies for fuzzing watermarking operations.

This module provides various PDF generation strategies to test different
edge cases, vulnerabilities, and error handling in PDF processing code.
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from atheris import FuzzedDataProvider


class PDFGenerationStrategy(IntEnum):
    """PDF generation strategies for fuzzing."""

    MINIMAL_VALID = 0
    JAVASCRIPT_PAYLOAD = 1
    NESTED_OBJECTS = 2
    LARGE_STREAM = 3
    MALICIOUS_ANNOTATIONS = 4
    MALFORMED_RANDOM = 5


def generate_minimal_valid_pdf(version: int = 7) -> bytes:
    """Generate a minimal valid PDF structure.

    Args:
        version: PDF version number (0-7 for PDF-1.0 through PDF-1.7)

    Returns:
        Minimal valid PDF as bytes
    """
    return f"""%PDF-1.{version}
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
xref
0 3
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
trailer
<< /Size 3 /Root 1 0 R >>
startxref
109
%%EOF
""".encode()


def generate_javascript_pdf(js_payload: str = "app.alert('test');") -> bytes:
    """Generate PDF with JavaScript payload (XSS/code execution test).

    Args:
        js_payload: JavaScript code to embed

    Returns:
        PDF with JavaScript as bytes
    """
    return f"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS ({js_payload}) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
%%EOF
""".encode()


def generate_nested_objects_pdf(depth: int = 50) -> bytes:
    """Generate PDF with deeply nested objects (stack overflow test).

    Args:
        depth: Number of nested object references

    Returns:
        PDF with nested objects as bytes (max 10KB)
    """
    pdf = b"%PDF-1.7\n"
    for i in range(depth):
        pdf += f"{i + 1} 0 obj\n<< /Next {i + 2} 0 R >>\nendobj\n".encode()
    pdf += b"%%EOF\n"
    return pdf[:10000]  # Limit to 10KB


def generate_large_stream_pdf(size: int = 50000, char: str = "A") -> bytes:
    """Generate PDF with large stream (memory exhaustion test).

    Args:
        size: Size of the stream in bytes
        char: Character to fill the stream with

    Returns:
        PDF with large stream as bytes
    """
    return f"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Length {size} >>
stream
{char * size}
endstream
endobj
%%EOF
""".encode()


def generate_malicious_annotations_pdf(action: str = "/JavaScript") -> bytes:
    """Generate PDF with malicious annotations/actions.

    Args:
        action: PDF action type to test (e.g., /Launch, /JavaScript)

    Returns:
        PDF with malicious annotations as bytes
    """
    return f"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>
endobj
4 0 obj
<< /Type /Annot /Subtype /Link /A << /S {action} >> >>
endobj
%%EOF
""".encode()


def generate_malformed_pdf(fdp: FuzzedDataProvider) -> bytes:
    """Generate malformed PDF with random bytes.

    Args:
        fdp: Atheris FuzzedDataProvider for random data

    Returns:
        Malformed PDF as bytes (max 10KB)
    """
    pdf = f"%PDF-1.{fdp.ConsumeIntInRange(0, 9)}".encode()
    pdf += fdp.ConsumeBytes(min(8192, fdp.remaining_bytes()))
    if b"%%EOF" not in pdf:
        pdf += b"\n%%EOF\n"
    return pdf[:10000]


def generate_fuzzed_pdf(fdp: FuzzedDataProvider) -> bytes:
    """Generate a fuzzed PDF using various strategies.

    This function randomly selects a PDF generation strategy and creates
    a corresponding PDF for testing. Strategies include:
    - Minimal valid PDF
    - JavaScript payloads (XSS test)
    - Deeply nested objects (stack overflow)
    - Large streams (memory exhaustion)
    - Malicious annotations (code execution)
    - Malformed PDFs (random bytes)

    Args:
        fdp: Atheris FuzzedDataProvider for randomness

    Returns:
        Generated PDF as bytes
    """
    strategy = PDFGenerationStrategy(fdp.ConsumeIntInRange(0, 5))

    if strategy == PDFGenerationStrategy.MINIMAL_VALID:
        version = fdp.ConsumeIntInRange(0, 7)
        return generate_minimal_valid_pdf(version)

    elif strategy == PDFGenerationStrategy.JAVASCRIPT_PAYLOAD:
        js_payload = fdp.ConsumeUnicodeNoSurrogates(128) or "app.alert('test');"
        return generate_javascript_pdf(js_payload)

    elif strategy == PDFGenerationStrategy.NESTED_OBJECTS:
        depth = fdp.ConsumeIntInRange(10, 100)
        return generate_nested_objects_pdf(depth)

    elif strategy == PDFGenerationStrategy.LARGE_STREAM:
        size = fdp.ConsumeIntInRange(1000, 100000)
        char = chr(fdp.ConsumeIntInRange(32, 126))
        return generate_large_stream_pdf(size, char)

    elif strategy == PDFGenerationStrategy.MALICIOUS_ANNOTATIONS:
        action = fdp.PickValueInList(
            [
                "/Launch",
                "/GoToR",
                "/ImportData",
                "/SubmitForm",
                "/JavaScript",
            ]
        )
        return generate_malicious_annotations_pdf(action)

    else:  # MALFORMED_RANDOM
        return generate_malformed_pdf(fdp)
