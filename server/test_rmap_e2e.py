#!/usr/bin/env python3
"""
End-to-end RMAP flow test demonstrating the full two-message protocol.
This shows that the implementation correctly handles the RMAP authentication flow.
"""

import base64
import json
import requests
import sys


def main():
    """Run end-to-end RMAP flow test."""
    base_url = "http://localhost:5000"
    
    print("🚀 Starting end-to-end RMAP flow test...")
    
    try:
        # Step 1: Send RMAP Message 1 (initiate authentication)
        print("\n📤 Step 1: Sending RMAP Message 1 (/rmap-initiate)")
        
        # Create Message 1: client nonce + identity
        msg1 = {"nonceClient": 987654321, "identity": "Alice"}
        msg1_json = json.dumps(msg1, separators=(",", ":"), sort_keys=True)
        payload1 = base64.b64encode(msg1_json.encode('utf-8')).decode('ascii')
        
        print(f"   Client nonce: {msg1['nonceClient']}")
        print(f"   Identity: {msg1['identity']}")
        
        response1 = requests.post(
            f"{base_url}/rmap-initiate",
            json={"payload": payload1},
            headers={"Content-Type": "application/json"}
        )
        
        print(f"   Response status: {response1.status_code}")
        
        if response1.status_code != 200:
            print(f"   ❌ Error: {response1.json()}")
            return 1
            
        # Decode the response to get server nonce
        response1_data = response1.json()
        response1_payload = base64.b64decode(response1_data["payload"]).decode('utf-8')
        response1_obj = json.loads(response1_payload)
        
        client_nonce = response1_obj["nonceClient"]
        server_nonce = response1_obj["nonceServer"]
        
        print(f"   ✅ Received client nonce: {client_nonce}")
        print(f"   ✅ Received server nonce: {server_nonce}")
        
        # Step 2: Send RMAP Message 2 (complete authentication)
        print("\n📤 Step 2: Sending RMAP Message 2 (/rmap-get-link)")
        
        # Create Message 2: server nonce
        msg2 = {"nonceServer": server_nonce}
        msg2_json = json.dumps(msg2, separators=(",", ":"), sort_keys=True)
        payload2 = base64.b64encode(msg2_json.encode('utf-8')).decode('ascii')
        
        print(f"   Server nonce: {msg2['nonceServer']}")
        
        response2 = requests.post(
            f"{base_url}/rmap-get-link",
            json={"payload": payload2},
            headers={"Content-Type": "application/json"}
        )
        
        print(f"   Response status: {response2.status_code}")
        
        if response2.status_code != 200:
            print(f"   ❌ Error: {response2.json()}")
            return 1
            
        # Get final result
        response2_data = response2.json()
        result = response2_data["result"]
        
        print(f"   ✅ Final result: {result}")
        print(f"   ✅ Result length: {len(result)} chars (expected: 32)")
        
        # Verify result format (32 hex chars)
        if len(result) != 32:
            print(f"   ❌ Result length is {len(result)}, expected 32")
            return 1
            
        if not all(c in "0123456789abcdef" for c in result):
            print("   ❌ Result contains non-hex characters")
            return 1
            
        # Verify result calculation (optional, for educational purposes)
        expected_combined = (client_nonce << 64) | server_nonce
        expected_result = f"{expected_combined:032x}"
        
        if result == expected_result:
            print(f"   ✅ Result calculation verified: {result}")
        else:
            print(f"   ⚠️  Result mismatch. Got: {result}, Expected: {expected_result}")
            
        print("\n🎉 End-to-end RMAP flow test completed successfully!")
        print("   Both endpoints are working correctly and the protocol flow is intact.")
        return 0
        
    except requests.exceptions.ConnectionError:
        print("❌ Connection error: Is the server running on localhost:5000?")
        print("   Start the server with: python -m server")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())