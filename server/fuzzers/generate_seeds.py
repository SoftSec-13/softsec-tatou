#!/usr/bin/env python3
"""Generate seed files for PDF fuzzers.

This script creates a comprehensive set of PDF test cases including:
- Valid PDFs with various structures
- Edge cases (minimal, empty, etc.)
- Malformed PDFs with common corruption patterns
- PDFs with different versions
- PDFs with metadata, annotations, images, etc.
"""

import os
import sys


def generate_pdf_seeds(output_dir):
    """Generate comprehensive PDF seed files."""
    
    seeds = []
    
    # ============================================================
    # VALID MINIMAL PDFs
    # ============================================================
    
    # Seed 001: Absolute minimal valid PDF
    seeds.append((
        "001_minimal_valid.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 002: Minimal with single empty page
    seeds.append((
        "002_minimal_one_page.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 003: PDF 1.0 version
    seeds.append((
        "003_pdf_v1.0.pdf",
        b"%PDF-1.0\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 004: PDF 1.1 version
    seeds.append((
        "004_pdf_v1.1.pdf",
        b"%PDF-1.1\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 005: PDF 1.2 version
    seeds.append((
        "005_pdf_v1.2.pdf",
        b"%PDF-1.2\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 006: PDF 1.3 version
    seeds.append((
        "006_pdf_v1.3.pdf",
        b"%PDF-1.3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 007: PDF 1.4 version
    seeds.append((
        "007_pdf_v1.4.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 008: PDF 1.5 version
    seeds.append((
        "008_pdf_v1.5.pdf",
        b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 009: PDF 1.6 version
    seeds.append((
        "009_pdf_v1.6.pdf",
        b"%PDF-1.6\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 010: PDF 1.7 version
    seeds.append((
        "010_pdf_v1.7.pdf",
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 011: PDF 2.0 version
    seeds.append((
        "011_pdf_v2.0.pdf",
        b"%PDF-2.0\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH METADATA
    # ============================================================
    
    # Seed 012: PDF with Info dictionary
    seeds.append((
        "012_with_info.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Title (Test) /Author (Fuzzer) >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 013: PDF with XMP metadata
    seeds.append((
        "013_with_xmp.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Metadata 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Metadata /Subtype /XML >>\nstream\n"
        b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>\n"
        b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>\n"
        b"</x:xmpmeta>\n"
        b"<?xpacket end='w'?>\n"
        b"endstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 014: PDF with multiple metadata entries
    seeds.append((
        "014_multi_metadata.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Title (A) /Author (B) /Subject (C) /Keywords (D) >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH PAGES
    # ============================================================
    
    # Seed 015: PDF with 2 pages
    seeds.append((
        "015_two_pages.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 016: PDF with 5 pages
    seeds.append((
        "016_five_pages.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R 7 0 R] /Count 5 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"5 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"6 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"7 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 017: PDF with MediaBox
    seeds.append((
        "017_with_mediabox.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH ANNOTATIONS
    # ============================================================
    
    # Seed 018: PDF with single annotation
    seeds.append((
        "018_with_annotation.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n"
        b"4 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 019: PDF with multiple annotations
    seeds.append((
        "019_multi_annotations.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R 5 0 R 6 0 R] >>\nendobj\n"
        b"4 0 obj\n<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>\nendobj\n"
        b"5 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] >>\nendobj\n"
        b"6 0 obj\n<< /Type /Annot /Subtype /FreeText /Rect [0 0 10 10] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH CONTENT STREAMS
    # ============================================================
    
    # Seed 020: PDF with simple content stream
    seeds.append((
        "020_with_content.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 44 >>\nstream\n"
        b"BT\n/F1 12 Tf\n100 700 Td\n(Hello) Tj\nET\n"
        b"endstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 021: PDF with font resource
    seeds.append((
        "021_with_font.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Font << /F1 5 0 R >> >>\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH CROSS-REFERENCE TABLES
    # ============================================================
    
    # Seed 022: PDF with xref table
    seeds.append((
        "022_with_xref.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n"
        b"0 2\n"
        b"0000000000 65535 f \n"
        b"0000000009 65535 n \n"
        b"trailer\n"
        b"<< /Size 2 /Root 1 0 R >>\n"
        b"startxref\n"
        b"50\n"
        b"%%EOF\n"
    ))
    
    # Seed 023: PDF with xref stream (PDF 1.5+)
    seeds.append((
        "023_xref_stream.pdf",
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Type /XRef /Length 10 >>\nstream\n"
        b"0123456789"
        b"endstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # EDGE CASES
    # ============================================================
    
    # Seed 024: Very short (just header)
    seeds.append((
        "024_header_only.pdf",
        b"%PDF-1.4\n"
    ))
    
    # Seed 025: Header with EOF
    seeds.append((
        "025_header_eof.pdf",
        b"%PDF-1.4\n%%EOF\n"
    ))
    
    # Seed 026: Single byte
    seeds.append((
        "026_single_byte.pdf",
        b"%"
    ))
    
    # Seed 027: Two bytes
    seeds.append((
        "027_two_bytes.pdf",
        b"%P"
    ))
    
    # Seed 028: Empty file
    seeds.append((
        "028_empty.pdf",
        b""
    ))
    
    # Seed 029: Just whitespace
    seeds.append((
        "029_whitespace.pdf",
        b"     \n\n\n   "
    ))
    
    # Seed 030: Very large PDF version number
    seeds.append((
        "030_large_version.pdf",
        b"%PDF-99.99\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # MALFORMED PDFs - Missing/Corrupted Headers
    # ============================================================
    
    # Seed 031: No header
    seeds.append((
        "031_no_header.pdf",
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 032: Corrupted header
    seeds.append((
        "032_corrupt_header.pdf",
        b"%XXX-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 033: Missing version
    seeds.append((
        "033_no_version.pdf",
        b"%PDF\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 034: Lowercase PDF
    seeds.append((
        "034_lowercase.pdf",
        b"%pdf-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 035: Extra characters in header
    seeds.append((
        "035_header_extra.pdf",
        b"%PDF-1.4 EXTRA\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # MALFORMED PDFs - Missing/Corrupted EOF
    # ============================================================
    
    # Seed 036: No EOF marker
    seeds.append((
        "036_no_eof.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    ))
    
    # Seed 037: Corrupted EOF
    seeds.append((
        "037_corrupt_eof.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%XXX\n"
    ))
    
    # Seed 038: Multiple EOF markers
    seeds.append((
        "038_multi_eof.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n%%EOF\n%%EOF\n"
    ))
    
    # Seed 039: EOF in middle
    seeds.append((
        "039_eof_middle.pdf",
        b"%PDF-1.4\n%%EOF\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    ))
    
    # ============================================================
    # MALFORMED PDFs - Object Issues
    # ============================================================
    
    # Seed 040: Missing endobj
    seeds.append((
        "040_no_endobj.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\n%%EOF\n"
    ))
    
    # Seed 041: Duplicate object numbers
    seeds.append((
        "041_dup_objects.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"1 0 obj\n<< /Type /Pages >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 042: Missing object number
    seeds.append((
        "042_no_objnum.pdf",
        b"%PDF-1.4\nobj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 043: Invalid object number
    seeds.append((
        "043_bad_objnum.pdf",
        b"%PDF-1.4\nXYZ 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 044: Negative object number
    seeds.append((
        "044_neg_objnum.pdf",
        b"%PDF-1.4\n-1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # MALFORMED PDFs - Dictionary Issues
    # ============================================================
    
    # Seed 045: Missing closing >>
    seeds.append((
        "045_unclosed_dict.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog\nendobj\n%%EOF\n"
    ))
    
    # Seed 046: Missing opening <<
    seeds.append((
        "046_no_dict_open.pdf",
        b"%PDF-1.4\n1 0 obj\n/Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 047: Empty dictionary
    seeds.append((
        "047_empty_dict.pdf",
        b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 048: Nested dictionaries
    seeds.append((
        "048_nested_dict.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /A << /B << /C /D >> >> >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 049: Dictionary with arrays
    seeds.append((
        "049_dict_arrays.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Array [1 2 3] >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # MALFORMED PDFs - Stream Issues
    # ============================================================
    
    # Seed 050: Missing endstream
    seeds.append((
        "050_no_endstream.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 5 >>\nstream\n"
        b"12345"
        b"\nendobj\n%%EOF\n"
    ))
    
    # Seed 051: Wrong stream length
    seeds.append((
        "051_wrong_length.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 99 >>\nstream\n"
        b"12345"
        b"\nendstream\nendobj\n%%EOF\n"
    ))
    
    # Seed 052: Empty stream
    seeds.append((
        "052_empty_stream.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 0 >>\nstream\n"
        b"endstream\nendobj\n%%EOF\n"
    ))
    
    # Seed 053: Stream without length
    seeds.append((
        "053_no_length.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< >>\nstream\n"
        b"12345\n"
        b"endstream\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # SPECIAL CHARACTERS AND ENCODINGS
    # ============================================================
    
    # Seed 054: PDF with null bytes
    seeds.append((
        "054_with_nulls.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Cata\x00log >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 055: PDF with high bytes
    seeds.append((
        "055_high_bytes.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Data (\xff\xfe\xfd) >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 056: PDF with UTF-8 BOM
    seeds.append((
        "056_utf8_bom.pdf",
        b"\xef\xbb\xbf%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 057: PDF with Unicode
    seeds.append((
        "057_unicode.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title (\xc3\xa9\xc3\xa0) >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 058: PDF with special chars in strings
    seeds.append((
        "058_special_chars.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Data (\\n\\r\\t) >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # LINEARIZED PDFs
    # ============================================================
    
    # Seed 059: Linearized PDF marker
    seeds.append((
        "059_linearized.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Linearized 1 >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH ENCRYPTION/SECURITY
    # ============================================================
    
    # Seed 060: PDF with Encrypt dict
    seeds.append((
        "060_with_encrypt.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Encrypt 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Filter /Standard /V 1 /R 2 >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # COMPRESSED OBJECTS
    # ============================================================
    
    # Seed 061: Object stream
    seeds.append((
        "061_objstream.pdf",
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /ObjStm /N 2 /First 10 /Length 20 >>\nstream\n"
        b"2 0 3 0 << >> << >>"
        b"\nendstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH NAMES
    # ============================================================
    
    # Seed 062: PDF with Names dictionary
    seeds.append((
        "062_with_names.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Names 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Dests 3 0 R >>\nendobj\n"
        b"3 0 obj\n<< >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH ACTIONS
    # ============================================================
    
    # Seed 063: PDF with OpenAction
    seeds.append((
        "063_open_action.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /GoTo >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH OUTLINES
    # ============================================================
    
    # Seed 064: PDF with Outlines
    seeds.append((
        "064_with_outlines.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Outlines 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Outlines /Count 0 >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # PDFs WITH EMBEDDED FILES
    # ============================================================
    
    # Seed 065: PDF with embedded file
    seeds.append((
        "065_embedded_file.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n"
        b"2 0 obj\n<< /Names [] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # VARIOUS SIZE PDFs
    # ============================================================
    
    # Seed 066: Very large object number
    seeds.append((
        "066_large_objnum.pdf",
        b"%PDF-1.4\n999999 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 067: Many objects (20+)
    pdf_many_objs = b"%PDF-1.4\n"
    for i in range(1, 21):
        pdf_many_objs += f"{i} 0 obj\n<< /Type /Test{i} >>\nendobj\n".encode()
    pdf_many_objs += b"%%EOF\n"
    seeds.append(("067_many_objects.pdf", pdf_many_objs))
    
    # Seed 068: Large content (1KB)
    seeds.append((
        "068_large_content.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Length 1024 >>\nstream\n" +
        b"A" * 1024 +
        b"\nendstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # INDIRECT REFERENCES
    # ============================================================
    
    # Seed 069: Indirect object reference
    seeds.append((
        "069_indirect_ref.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 070: Circular references
    seeds.append((
        "070_circular_ref.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Next 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Test /Next 1 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 071: Self reference
    seeds.append((
        "071_self_ref.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Self 1 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 072: Dangling reference
    seeds.append((
        "072_dangling_ref.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Missing 999 0 R >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # FILTERS AND COMPRESSION
    # ============================================================
    
    # Seed 073: FlateDecode filter
    seeds.append((
        "073_flate_filter.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 10 /Filter /FlateDecode >>\nstream\n"
        b"x\x9c+I-.q\x04\x00\x04]\x01\xc1"
        b"\nendstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 074: Multiple filters
    seeds.append((
        "074_multi_filter.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Length 5 /Filter [/ASCIIHexDecode /FlateDecode] >>\nstream\n"
        b"12345"
        b"\nendstream\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # COMMENTS AND WHITESPACE
    # ============================================================
    
    # Seed 075: PDF with comments
    seeds.append((
        "075_with_comments.pdf",
        b"%PDF-1.4\n"
        b"% This is a comment\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"% Another comment\n"
        b"%%EOF\n"
    ))
    
    # Seed 076: Excessive whitespace
    seeds.append((
        "076_whitespace.pdf",
        b"%PDF-1.4\n\n\n\n"
        b"1   0   obj\n<<   /Type   /Catalog   >>\nendobj\n\n\n"
        b"%%EOF\n"
    ))
    
    # Seed 077: No whitespace
    seeds.append((
        "077_no_whitespace.pdf",
        b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
    ))
    
    # Seed 078: Tabs instead of spaces
    seeds.append((
        "078_tabs.pdf",
        b"%PDF-1.4\n1\t0\tobj\n<<\t/Type\t/Catalog\t>>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # NUMERIC EDGE CASES
    # ============================================================
    
    # Seed 079: Float numbers
    seeds.append((
        "079_floats.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Value 3.14159 >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 080: Negative numbers
    seeds.append((
        "080_negative.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Value -42 >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 081: Very large numbers
    seeds.append((
        "081_large_num.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Value 999999999 >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 082: Scientific notation
    seeds.append((
        "082_scientific.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Value 1.23e10 >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # STRING VARIATIONS
    # ============================================================
    
    # Seed 083: Literal strings
    seeds.append((
        "083_literal_string.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title (Hello World) >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 084: Hex strings
    seeds.append((
        "084_hex_string.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title <48656C6C6F> >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 085: Nested parentheses
    seeds.append((
        "085_nested_parens.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title (A (nested) string) >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 086: Escaped characters
    seeds.append((
        "086_escaped.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title (Line\\nBreak\\tTab) >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 087: Empty string
    seeds.append((
        "087_empty_string.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Title () >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # ARRAY VARIATIONS
    # ============================================================
    
    # Seed 088: Simple array
    seeds.append((
        "088_simple_array.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Array [1 2 3] >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 089: Nested arrays
    seeds.append((
        "089_nested_array.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Array [1 [2 3] 4] >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 090: Empty array
    seeds.append((
        "090_empty_array.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Array [] >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 091: Array with mixed types
    seeds.append((
        "091_mixed_array.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Array [1 (string) /Name true] >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # BOOLEAN AND NULL
    # ============================================================
    
    # Seed 092: Boolean true
    seeds.append((
        "092_bool_true.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Flag true >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 093: Boolean false
    seeds.append((
        "093_bool_false.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Flag false >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 094: Null value
    seeds.append((
        "094_null.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Value null >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # NAME OBJECTS
    # ============================================================
    
    # Seed 095: Name with special chars
    seeds.append((
        "095_name_special.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Name#20With#20Spaces >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 096: Very long name
    seeds.append((
        "096_long_name.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /VeryLongNameWithManyCharacters123456789 >>\nendobj\n%%EOF\n"
    ))
    
    # ============================================================
    # TRAILER VARIATIONS
    # ============================================================
    
    # Seed 097: Trailer with Size
    seeds.append((
        "097_trailer_size.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\n"
        b"%%EOF\n"
    ))
    
    # Seed 098: Trailer with ID
    seeds.append((
        "098_trailer_id.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /ID [<1234> <5678>] >>\n"
        b"%%EOF\n"
    ))
    
    # Seed 099: Trailer with Info
    seeds.append((
        "099_trailer_info.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Title (Test) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /Info 2 0 R >>\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # INCREMENTAL UPDATES
    # ============================================================
    
    # Seed 100: PDF with incremental update
    seeds.append((
        "100_incremental.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"%%EOF\n"
        b"2 0 obj\n<< /Type /Pages >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # ============================================================
    # ADDITIONAL EDGE CASES (101-120)
    # ============================================================
    
    # Seed 101: PDF with only comment
    seeds.append((
        "101_only_comment.pdf",
        b"% This is just a comment\n"
    ))
    
    # Seed 102: PDF header with spaces
    seeds.append((
        "102_header_spaces.pdf",
        b"% PDF - 1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 103: CR line endings
    seeds.append((
        "103_cr_endings.pdf",
        b"%PDF-1.4\r1 0 obj\r<< /Type /Catalog >>\rendobj\r%%EOF\r"
    ))
    
    # Seed 104: CRLF line endings
    seeds.append((
        "104_crlf_endings.pdf",
        b"%PDF-1.4\r\n1 0 obj\r\n<< /Type /Catalog >>\r\nendobj\r\n%%EOF\r\n"
    ))
    
    # Seed 105: Mixed line endings
    seeds.append((
        "105_mixed_endings.pdf",
        b"%PDF-1.4\r\n1 0 obj\n<< /Type /Catalog >>\r\nendobj\n%%EOF\r"
    ))
    
    # Seed 106: Binary data in comment
    seeds.append((
        "106_binary_comment.pdf",
        b"%PDF-1.4\n%\xff\xfe\xfd\xfc\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 107: PDF with form
    seeds.append((
        "107_with_form.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /AcroForm 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Fields [] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 108: PDF with JavaScript
    seeds.append((
        "108_with_js.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Names << /JavaScript 2 0 R >> >>\nendobj\n"
        b"2 0 obj\n<< /Names [] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 109: PDF with structure tree
    seeds.append((
        "109_struct_tree.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /StructTreeRoot 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /StructTreeRoot >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 110: PDF with page labels
    seeds.append((
        "110_page_labels.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /PageLabels << /Nums [0 << /S /D >>] >> >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 111: Object with generation > 0
    seeds.append((
        "111_gen_num.pdf",
        b"%PDF-1.4\n1 5 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 112: Very short stream
    seeds.append((
        "112_short_stream.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Length 1 >>\nstream\nX\nendstream\nendobj\n%%EOF\n"
    ))
    
    # Seed 113: Stream with binary data
    seeds.append((
        "113_binary_stream.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Length 10 >>\nstream\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\nendstream\nendobj\n%%EOF\n"
    ))
    
    # Seed 114: PDF with viewer preferences
    seeds.append((
        "114_viewer_prefs.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /ViewerPreferences << /HideToolbar true >> >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 115: PDF with page mode
    seeds.append((
        "115_page_mode.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /PageMode /UseOutlines >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 116: PDF with page layout
    seeds.append((
        "116_page_layout.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /PageLayout /TwoColumnLeft >>\nendobj\n%%EOF\n"
    ))
    
    # Seed 117: PDF with threads
    seeds.append((
        "117_with_threads.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Threads [] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 118: PDF with OCG (Optional Content)
    seeds.append((
        "118_with_ocg.pdf",
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /OCProperties << /OCGs [] /D << /Order [] >> >> >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 119: PDF with requirements
    seeds.append((
        "119_requirements.pdf",
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Requirements [] >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Seed 120: PDF with collection
    seeds.append((
        "120_collection.pdf",
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Collection << /Type /Collection >> >>\nendobj\n"
        b"%%EOF\n"
    ))
    
    # Write all seeds to disk
    os.makedirs(output_dir, exist_ok=True)
    for filename, content in seeds:
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        print(f"Created: {filename} ({len(content)} bytes)")
    
    print(f"\nTotal seeds created: {len(seeds)}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    else:
        # Default to both directories
        dirs = [
            os.path.join(os.path.dirname(__file__), "seeds", "watermarking"),
            os.path.join(os.path.dirname(__file__), "seeds", "pdf_exploration")
        ]
        for d in dirs:
            print(f"\n{'='*60}")
            print(f"Generating seeds in: {d}")
            print('='*60)
            generate_pdf_seeds(d)
    
    if len(sys.argv) > 1:
        generate_pdf_seeds(sys.argv[1])
