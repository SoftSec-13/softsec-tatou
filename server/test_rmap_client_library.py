#!/usr/bin/env python3
"""
RMAP Client Library Test Script

This script emulates the functionality that would be provided by the official
RMAP library (rmap.identity_manager.IdentityManager and rmap.rmap.RMAP)
but uses our GPG-based implementation.

This follows the pattern requested in the comment:
- Initialize client with Group's keys
- Create properly formatted RMAP messages
- Test both Message 1 and Message 2
- Handle watermarked PDF creation
"""

import sys
import os
import base64
import json
import requests
import subprocess
import tempfile
from pathlib import Path

# Add the server src directory to the path to import modules
sys.path.insert(0, '/home/runner/work/softsec-tatou/softsec-tatou/server/src')
import watermarking_utils as WMUtils

SERVER_URL = "http://localhost:5000"

class IdentityManager:
    """Emulates the RMAP IdentityManager functionality."""
    
    def __init__(self, client_keys_dir: str, client_private_key_path: str, 
                 client_public_key_path: str, server_public_key_path: str):
        self.client_keys_dir = client_keys_dir
        self.client_private_key_path = client_private_key_path
        self.client_public_key_path = client_public_key_path
        self.server_public_key_path = server_public_key_path
        self.server_email = "server@tatou.example.com"
        
        # Import keys
        self._import_keys()
        
    def _import_keys(self):
        """Import client and server keys."""
        try:
            subprocess.run(['gpg', '--import', self.client_private_key_path], 
                         check=True, capture_output=True)
            subprocess.run(['gpg', '--import', self.client_public_key_path],
                         check=True, capture_output=True)
            subprocess.run(['gpg', '--import', self.server_public_key_path],
                         check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # Keys might already be imported
            pass

class RMAP:
    """Emulates the RMAP client functionality."""
    
    def __init__(self, identity_manager: IdentityManager):
        self.identity_manager = identity_manager
        self.server_nonce = None
        
    def create_message1(self, identity: str) -> dict:
        """Create Message 1 for RMAP authentication."""
        import secrets
        
        # Generate client nonce
        client_nonce = secrets.randbits(64)
        
        # Create message data
        message_data = {
            "nonceClient": client_nonce,
            "identity": identity
        }
        
        # Store for later use
        self.client_nonce = client_nonce
        self.identity = identity
        
        # Encrypt for server
        encrypted_payload = self._encrypt_for_server(message_data)
        
        return {"payload": encrypted_payload}
    
    def process_response1(self, response: dict) -> dict:
        """Process the response from Message 1."""
        # Decrypt the server response
        decrypted = self._decrypt_from_server(response["payload"])
        
        # Verify client nonce matches
        if decrypted["nonceClient"] != self.client_nonce:
            raise ValueError("Client nonce mismatch")
        
        # Store server nonce
        self.server_nonce = decrypted["nonceServer"]
        
        return decrypted
    
    def create_message2(self, result: dict) -> dict:
        """Create Message 2 with server nonce."""
        message_data = {
            "nonceServer": self.server_nonce
        }
        
        # Encrypt for server
        encrypted_payload = self._encrypt_for_server(message_data)
        
        return {"payload": encrypted_payload}
    
    def _encrypt_for_server(self, message_data: dict) -> str:
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
                '--recipient', self.identity_manager.server_email, '--output', temp_output, temp_input
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
    
    def _decrypt_from_server(self, encrypted_base64: str) -> dict:
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


def test_rmap_client_library():
    """Test the RMAP implementation using the client library pattern."""
    print("=== RMAP Client Library Test ===")
    
    # Initialize client with Group 13's keys
    print("1. Initializing RMAP client for Group 13...")
    
    try:
        client_identity_manager = IdentityManager(
            client_keys_dir="/home/runner/work/softsec-tatou/softsec-tatou/server/src/client_keys/pki",
            client_private_key_path="/home/runner/work/softsec-tatou/softsec-tatou/server/Group13_priv.asc",
            client_public_key_path="/home/runner/work/softsec-tatou/softsec-tatou/server/src/client_keys/pki/Group_13.asc",
            server_public_key_path="/home/runner/work/softsec-tatou/softsec-tatou/server/server_pub.asc"
        )
        print("   ✓ Identity manager initialized")
    except Exception as e:
        print(f"   ✗ Failed to initialize identity manager: {e}")
        return False
    
    try:
        client_rmap = RMAP(client_identity_manager)
        print("   ✓ RMAP client initialized")
    except Exception as e:
        print(f"   ✗ Failed to initialize RMAP client: {e}")
        return False
    
    # Test Message 1
    print("\n2. Creating and sending Message 1...")
    
    try:
        message1 = client_rmap.create_message1("Group13")
        print("   ✓ Message 1 created and encrypted")
    except Exception as e:
        print(f"   ✗ Failed to create Message 1: {e}")
        return False
    
    # Send to server
    try:
        response = requests.post('http://localhost:5000/rmap-initiate', 
                                json={"payload": message1['payload']})
        print(f"   ✓ Message 1 sent to server")
        print(f"   ✓ Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"   ✗ Server error: {response.json()}")
            return False
            
        print("   ✓ Message 1 successful")
        
    except Exception as e:
        print(f"   ✗ Failed to send Message 1: {e}")
        return False
    
    # Process response and create Message 2
    print("\n3. Processing response and creating Message 2...")
    
    try:
        result = client_rmap.process_response1(response.json())
        print("   ✓ Response decrypted and processed")
        print(f"   ✓ Server nonce: {result['nonceServer']}")
        print(f"   ✓ Client nonce confirmed: {result['nonceClient']}")
    except Exception as e:
        print(f"   ✗ Failed to process response: {e}")
        return False
    
    try:
        message2 = client_rmap.create_message2(result)
        print("   ✓ Message 2 created and encrypted")
    except Exception as e:
        print(f"   ✗ Failed to create Message 2: {e}")
        return False
    
    # Send Message 2
    try:
        response2 = requests.post('http://localhost:5000/rmap-get-link',
                                 json={"payload": message2['payload']})
        print(f"   ✓ Message 2 sent to server")
        print(f"   ✓ Response status: {response2.status_code}")
        
        if response2.status_code != 200:
            print(f"   ✗ Server error: {response2.json()}")
            return False
            
        print("   ✓ Message 2 successful")
        
    except Exception as e:
        print(f"   ✗ Failed to send Message 2: {e}")
        return False
    
    # Get the session secret (PDF link)
    try:
        pdf_link = response2.json().get('result')
        print(f"   ✓ Session secret (PDF link): {pdf_link}")
        
        if not pdf_link or len(pdf_link) != 32:
            print(f"   ✗ Invalid session secret format")
            return False
            
        print("   ✓ Valid session secret received")
        
    except Exception as e:
        print(f"   ✗ Failed to get session secret: {e}")
        return False
    
    # Test watermarked PDF creation with the session secret
    print("\n4. Creating watermarked PDF with session secret...")
    
    try:
        # Create a test PDF
        import fitz
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 100), f"RMAP Authenticated Document - Group 13", fontsize=16)
        page.insert_text((50, 150), f"Session Secret: {pdf_link}", fontsize=10)
        
        test_pdf_path = "/tmp/rmap_library_test.pdf"
        doc.save(test_pdf_path)
        doc.close()
        
        print(f"   ✓ Test PDF created: {Path(test_pdf_path).name}")
        
        # Watermark the PDF with session secret
        method = "robust-xmp"
        key = f"rmap-key-{pdf_link[:8]}"
        
        watermarked_bytes = WMUtils.apply_watermark(
            method=method,
            pdf=test_pdf_path,
            secret=pdf_link,
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
        
        if read_secret == pdf_link:
            print(f"   ✓ Watermark verification successful!")
            print(f"   ✓ RMAP session secret preserved in PDF")
        else:
            print(f"   ✗ Watermark verification failed!")
            return False
            
    except Exception as e:
        print(f"   ✗ PDF watermarking failed: {e}")
        return False
    
    print(f"\n✅ RMAP CLIENT LIBRARY TEST SUCCESSFUL!")
    print(f"   • RMAP client library functionality: ✓")
    print(f"   • Group 13 authentication: ✓")
    print(f"   • Message 1/Message 2 exchange: ✓")
    print(f"   • Session secret generation: ✓")
    print(f"   • PDF watermarking integration: ✓")
    print(f"   • End-to-end encryption/decryption: ✓")
    
    return True


def repeat_test(times=2):
    """Repeat the test multiple times as requested."""
    print(f"=== Running RMAP Test {times} Times ===\n")
    
    for i in range(times):
        print(f"--- Test Run {i+1}/{times} ---")
        success = test_rmap_client_library()
        if not success:
            print(f"\n❌ Test run {i+1} failed!")
            return False
        print(f"\n✅ Test run {i+1} completed successfully!\n")
    
    print(f"🎉 All {times} test runs completed successfully!")
    return True


if __name__ == "__main__":
    # Run the test twice as requested in the comment
    success = repeat_test(2)
    sys.exit(0 if success else 1)