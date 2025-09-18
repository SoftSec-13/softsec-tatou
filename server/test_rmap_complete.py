#!/usr/bin/env python3
"""
Complete RMAP test script that properly handles the two-step authentication protocol.
"""

import base64
import json
import requests

SERVER_URL = "http://localhost:5000"

def test_rmap_complete():
    print("=== Complete RMAP Test ===")
    
    # Step 1: Create message 1 (client nonce + identity)
    client_nonce = 12345678901234567890  # 64-bit nonce
    identity = "Group13"
    
    message1_data = {
        "nonceClient": client_nonce,
        "identity": identity
    }
    
    message1_json = json.dumps(message1_data)
    message1_payload = base64.b64encode(message1_json.encode('utf-8')).decode('utf-8')
    
    print(f"1. Sending /rmap-initiate with client nonce: {client_nonce}")
    print(f"   Identity: {identity}")
    
    # Send message 1
    response1 = requests.post(
        f"{SERVER_URL}/rmap-initiate",
        json={"payload": message1_payload}
    )
    
    print(f"   Response status: {response1.status_code}")
    
    if response1.status_code != 200:
        print(f"   Error: {response1.json()}")
        return False
    
    # Decode response 1
    response1_data = response1.json()
    response1_payload = response1_data["payload"]
    response1_decoded = base64.b64decode(response1_payload).decode('utf-8')
    response1_json = json.loads(response1_decoded)
    
    server_nonce = response1_json["nonceServer"]
    returned_client_nonce = response1_json["nonceClient"]
    
    print(f"   Server nonce received: {server_nonce}")
    print(f"   Client nonce confirmed: {returned_client_nonce}")
    
    if returned_client_nonce != client_nonce:
        print("   ERROR: Client nonce mismatch!")
        return False
    
    # Step 2: Create message 2 (server nonce)
    message2_data = {
        "nonceServer": server_nonce
    }
    
    message2_json = json.dumps(message2_data)
    message2_payload = base64.b64encode(message2_json.encode('utf-8')).decode('utf-8')
    
    print(f"\n2. Sending /rmap-get-link with server nonce: {server_nonce}")
    
    # Send message 2
    response2 = requests.post(
        f"{SERVER_URL}/rmap-get-link",
        json={"payload": message2_payload}
    )
    
    print(f"   Response status: {response2.status_code}")
    
    if response2.status_code != 200:
        print(f"   Error: {response2.json()}")
        return False
    
    # Get session secret
    response2_data = response2.json()
    session_secret = response2_data["result"]
    
    print(f"   Session secret: {session_secret}")
    print(f"   Session secret length: {len(session_secret)} characters")
    
    # Verify session secret format (should be 32 hex characters)
    if len(session_secret) != 32:
        print("   ERROR: Session secret should be 32 hex characters!")
        return False
    
    try:
        int(session_secret, 16)  # Verify it's valid hex
        print("   ✓ Session secret is valid hex")
    except ValueError:
        print("   ERROR: Session secret is not valid hex!")
        return False
    
    print("\n=== RMAP Test SUCCESSFUL! ===")
    return True

if __name__ == "__main__":
    success = test_rmap_complete()
    exit(0 if success else 1)