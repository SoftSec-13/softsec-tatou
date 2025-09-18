#!/usr/bin/env python3
"""
Complete RMAP client implementation that can encrypt/decrypt messages.

This script demonstrates a complete RMAP client that:
1. Encrypts messages for the server
2. Decrypts server responses 
3. Handles the complete two-step protocol
4. Creates watermarked PDFs using session secrets
"""

import sys
import base64
import json
import requests
import subprocess
import tempfile
import os
from pathlib import Path

# Add the server src directory to the path to import modules
sys.path.insert(0, '/home/runner/work/softsec-tatou/softsec-tatou/server/src')
import watermarking_utils as WMUtils

SERVER_URL = "http://localhost:5000"

class RMAPClient:
    """RMAP client with GPG encryption/decryption capabilities."""
    
    def __init__(self, identity: str, private_key_path: str, server_public_key_path: str):
        self.identity = identity
        self.private_key_path = private_key_path
        self.server_public_key_path = server_public_key_path
        self.server_email = "server@tatou.example.com"
        self.client_email = f"{identity.lower()}@tatou.example.com"
        
        # Import keys
        self._import_keys()
        
    def _import_keys(self):
        """Import client and server keys."""
        try:
            subprocess.run(['gpg', '--import', self.private_key_path], 
                         check=True, capture_output=True)
            subprocess.run(['gpg', '--import', self.server_public_key_path],
                         check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # Keys might already be imported
            pass
            
    def encrypt_for_server(self, message_data: dict) -> str:
        """Encrypt a message for the server."""
        message_json = json.dumps(message_data)
        
        # Write message to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(message_json)
            temp_input = f.name
            
        with tempfile.NamedTemporaryFile(mode='rb', delete=False) as f:
            temp_output = f.name
            
        try:
            # Encrypt for server
            result = subprocess.run([
                'gpg', '--encrypt', '--armor', '--batch', '--yes', '--trust-model', 'always',
                '--recipient', self.server_email, '--output', temp_output, temp_input
            ], capture_output=True, text=True, check=True)
            
            # Read encrypted data
            with open(temp_output, 'rb') as f:
                encrypted_data = f.read()
                
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        finally:
            if os.path.exists(temp_input):
                os.unlink(temp_input)
            if os.path.exists(temp_output):
                os.unlink(temp_output)
                
    def decrypt_from_server(self, encrypted_base64: str) -> dict:
        """Decrypt a message from the server."""
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_base64)
        
        # Write to temp file for GPG
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(encrypted_data)
            temp_file = f.name
            
        try:
            # Decrypt using GPG
            result = subprocess.run([
                'gpg', '--decrypt', '--quiet', '--batch', '--yes', temp_file
            ], capture_output=True, text=True, check=True)
            
            decrypted_text = result.stdout
            return json.loads(decrypted_text)
            
        finally:
            os.unlink(temp_file)


def test_complete_rmap_with_watermarking():
    print("=== Complete RMAP + Watermarking Test ===")
    
    # Initialize RMAP client
    client = RMAPClient(
        identity="Group13",
        private_key_path="/home/runner/work/softsec-tatou/softsec-tatou/server/Group13_priv.asc",
        server_public_key_path="/home/runner/work/softsec-tatou/softsec-tatou/server/server_pub.asc"
    )
    
    # Step 1: RMAP Authentication - Message 1
    client_nonce = 12345678901234567890
    
    print(f"1. RMAP Step 1: Authenticating as {client.identity}")
    print(f"   Client nonce: {client_nonce}")
    
    try:
        message1_payload = client.encrypt_for_server({
            "nonceClient": client_nonce,
            "identity": client.identity
        })
        print(f"   ✓ Message 1 encrypted successfully")
    except Exception as e:
        print(f"   ✗ Message 1 encryption failed: {e}")
        return False
    
    # Send message 1 to server
    response1 = requests.post(
        f"{SERVER_URL}/rmap-initiate",
        json={"payload": message1_payload}
    )
    
    if response1.status_code != 200:
        print(f"   ✗ Server error: {response1.json()}")
        return False
    
    print(f"   ✓ Server accepted authentication request")
    
    # Decrypt server response
    try:
        response1_data = client.decrypt_from_server(response1.json()["payload"])
        server_nonce = response1_data["nonceServer"]
        returned_client_nonce = response1_data["nonceClient"]
        
        if returned_client_nonce != client_nonce:
            print(f"   ✗ Client nonce mismatch!")
            return False
            
        print(f"   ✓ Server nonce received: {server_nonce}")
        print(f"   ✓ Client nonce confirmed: {returned_client_nonce}")
        
    except Exception as e:
        print(f"   ✗ Failed to decrypt server response: {e}")
        return False
    
    # Step 2: RMAP Authentication - Message 2
    print(f"\n2. RMAP Step 2: Sending server nonce back")
    print(f"   Server nonce: {server_nonce}")
    
    try:
        message2_payload = client.encrypt_for_server({
            "nonceServer": server_nonce
        })
        print(f"   ✓ Message 2 encrypted successfully")
    except Exception as e:
        print(f"   ✗ Message 2 encryption failed: {e}")
        return False
    
    # Send message 2 to server
    response2 = requests.post(
        f"{SERVER_URL}/rmap-get-link",
        json={"payload": message2_payload}
    )
    
    if response2.status_code != 200:
        print(f"   ✗ Server error: {response2.json()}")
        return False
    
    # Get session secret
    session_secret = response2.json()["result"]
    print(f"   ✓ Session secret received: {session_secret}")
    
    # Verify session secret format
    if len(session_secret) != 32 or not all(c in '0123456789abcdef' for c in session_secret):
        print(f"   ✗ Invalid session secret format!")
        return False
    
    print(f"   ✓ Session secret is valid hex (32 characters)")
    
    # Step 3: Create watermarked PDF using session secret
    print(f"\n3. Creating watermarked PDF with session secret")
    
    # Create a test PDF
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 100), f"RMAP Authenticated Document", fontsize=16)
    page.insert_text((50, 150), f"Identity: {client.identity}", fontsize=12)
    page.insert_text((50, 180), f"Session: {session_secret}", fontsize=10)
    
    test_pdf_path = "/tmp/rmap_authenticated_test.pdf"
    doc.save(test_pdf_path)
    doc.close()
    
    print(f"   ✓ Test PDF created: {Path(test_pdf_path).name}")
    
    # Watermark the PDF with session secret
    try:
        method = "robust-xmp"
        key = f"rmap-key-{session_secret[:8]}"
        
        watermarked_bytes = WMUtils.apply_watermark(
            method=method,
            pdf=test_pdf_path,
            secret=session_secret,
            key=key
        )
        
        watermarked_path = test_pdf_path.replace('.pdf', '_watermarked.pdf')
        Path(watermarked_path).write_bytes(watermarked_bytes)
        
        print(f"   ✓ Watermarked PDF created: {Path(watermarked_path).name}")
        print(f"   ✓ Size: {len(watermarked_bytes)} bytes")
        
        # Verify watermark
        read_secret = WMUtils.read_watermark(
            method=method,
            pdf=watermarked_path,
            key=key
        )
        
        if read_secret == session_secret:
            print(f"   ✓ Watermark verification successful!")
            print(f"   ✓ RMAP session secret preserved in PDF")
        else:
            print(f"   ✗ Watermark verification failed!")
            return False
            
    except Exception as e:
        print(f"   ✗ Watermarking failed: {e}")
        return False
    
    print(f"\n✅ COMPLETE RMAP + WATERMARKING TEST SUCCESSFUL!")
    print(f"   • GPG-based RMAP authentication: ✓")
    print(f"   • Client/server nonce exchange: ✓")
    print(f"   • Session secret generation: ✓")
    print(f"   • PDF watermarking with session secret: ✓")
    print(f"   • Watermark verification: ✓")
    print(f"   • End-to-end encryption/decryption: ✓")
    
    return True

if __name__ == "__main__":
    success = test_complete_rmap_with_watermarking()
    sys.exit(0 if success else 1)