# type: ignore
#!/usr/bin/env python3
"""
Complete RMAP + Watermarking integration test.

This test demonstrates the full flow:
1. RMAP authentication to get session secret
2. Use session secret to watermark a PDF
3. Verify the watermark can be read back
"""

import base64
import json
import sys
import tempfile
from pathlib import Path

import requests

# Add the server src directory to the path to import modules
sys.path.insert(0, "/home/runner/work/softsec-tatou/softsec-tatou/server/src")
import watermarking_utils as WMUtils

SERVER_URL = "http://localhost:5000"


def create_simple_pdf():
    """Create a simple test PDF using PyMuPDF."""
    import fitz

    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 100), "RMAP Integration Test Document", fontsize=16)
    page.insert_text(
        (50, 150),
        "This PDF will be watermarked with an RMAP session secret.",
        fontsize=12,
    )

    # Use tempfile instead of hardcoded /tmp path
    with tempfile.NamedTemporaryFile(
        suffix=".pdf", delete=False, prefix="rmap_integration_test_"
    ) as tmp_file:
        pdf_path = tmp_file.name

    doc.save(pdf_path)
    doc.close()
    return pdf_path


def rmap_authenticate(identity="Group13"):
    """Perform RMAP authentication and return session secret."""
    print("=== RMAP Authentication ===")

    # Step 1: Create message 1 (client nonce + identity)
    client_nonce = 98765432109876543210  # 64-bit nonce

    message1_data = {"nonceClient": client_nonce, "identity": identity}

    message1_json = json.dumps(message1_data)
    message1_payload = base64.b64encode(message1_json.encode("utf-8")).decode("utf-8")

    print(f"1. Authenticating as: {identity}")

    # Send message 1 with timeout
    response1 = requests.post(
        f"{SERVER_URL}/rmap-initiate",
        json={"payload": message1_payload},
        timeout=10,  # Add timeout to fix security issue
    )

    if response1.status_code != 200:
        print(f"   ERROR: RMAP initiate failed: {response1.json()}")
        return None

    # Decode response 1
    response1_data = response1.json()
    response1_payload = response1_data["payload"]
    response1_decoded = base64.b64decode(response1_payload).decode("utf-8")
    response1_json = json.loads(response1_decoded)

    server_nonce = response1_json["nonceServer"]
    print(f"   ✓ Received server nonce: {server_nonce}")

    # Step 2: Create message 2 (server nonce)
    message2_data = {"nonceServer": server_nonce}
    message2_json = json.dumps(message2_data)
    message2_payload = base64.b64encode(message2_json.encode("utf-8")).decode("utf-8")

    # Send message 2 with timeout
    response2 = requests.post(
        f"{SERVER_URL}/rmap-get-link",
        json={"payload": message2_payload},
        timeout=10,  # Add timeout to fix security issue
    )

    if response2.status_code != 200:
        print(f"   ERROR: RMAP get-link failed: {response2.json()}")
        return None

    # Get session secret
    response2_data = response2.json()
    session_secret = response2_data["result"]

    print(f"   ✓ Session secret: {session_secret}")
    return session_secret


def watermark_pdf_with_rmap(pdf_path, session_secret):
    """Watermark a PDF using the RMAP session secret."""
    print("\n=== PDF Watermarking ===")

    method = "robust-xmp"
    key = f"rmap-key-{session_secret[:8]}"  # Derive key from session secret

    print(f"1. Watermarking {Path(pdf_path).name} with RMAP session secret")
    print(f"   Method: {method}")
    print(f"   Key: {key}")

    try:
        # Apply watermark
        watermarked_bytes = WMUtils.apply_watermark(
            method=method, pdf=pdf_path, secret=session_secret, key=key
        )

        # Save watermarked PDF
        watermarked_path = pdf_path.replace(".pdf", "_watermarked.pdf")
        Path(watermarked_path).write_bytes(watermarked_bytes)

        print(f"   ✓ Created watermarked PDF: {Path(watermarked_path).name}")
        print(f"   ✓ Size: {len(watermarked_bytes)} bytes")

        # Verify watermark
        read_secret = WMUtils.read_watermark(
            method=method, pdf=watermarked_path, key=key
        )

        if read_secret == session_secret:
            print("   ✓ Watermark verification successful!")
            print("   ✓ Read secret matches RMAP session secret")
            return watermarked_path
        else:
            print("   ✗ Watermark verification failed!")
            print(f"   Expected: {session_secret}")
            print(f"   Got: {read_secret}")
            return None

    except Exception as e:
        print(f"   ✗ Watermarking failed: {e}")
        return None


def main():
    print("=== RMAP + Watermarking Integration Test ===\n")

    # Create test PDF
    pdf_path = create_simple_pdf()
    print(f"Created test PDF: {Path(pdf_path).name}\n")

    # Perform RMAP authentication
    session_secret = rmap_authenticate("Group13")
    if not session_secret:
        print("\n❌ RMAP authentication failed!")
        return False

    # Watermark PDF with session secret
    watermarked_path = watermark_pdf_with_rmap(pdf_path, session_secret)
    if not watermarked_path:
        print("\n❌ PDF watermarking failed!")
        return False

    print("\n✅ INTEGRATION TEST SUCCESSFUL!")
    print("   • RMAP authentication: ✓")
    print("   • PDF watermarking: ✓")
    print("   • Watermark verification: ✓")
    print("   • Session secret preserved in PDF: ✓")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
