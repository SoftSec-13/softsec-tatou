#!/usr/bin/env python3
"""
Dynamic RMAP test that creates Message 2 at runtime by decrypting the server response.
"""

import base64
import getpass
import json
from pathlib import Path

import requests

try:
    from pgpy import PGPKey, PGPMessage
except ImportError:
    print("Error: pgpy library not found. Install with: pip install pgpy")
    exit(1)


SERVER_URL = "http://localhost:5000"


def load_server_public_key():
    """Load the server's public key."""
    server_pub_path = Path("src/server_pub.asc")
    if not server_pub_path.exists():
        raise FileNotFoundError(f"Server public key not found: {server_pub_path}")

    key, _ = PGPKey.from_file(str(server_pub_path))
    return key


def load_group13_private_key():
    """Load Group 13's private key with password if needed."""
    group13_priv_path = Path("../private_key_group_13.asc")
    if not group13_priv_path.exists():
        raise FileNotFoundError(f"Group 13 private key not found: {group13_priv_path}")

    key, _ = PGPKey.from_file(str(group13_priv_path))

    # Check if key is password protected
    if key.is_protected:
        print("Group 13 private key is password protected.")
        max_attempts = 3
        for attempt in range(max_attempts):
            password = getpass.getpass(
                f"Enter password for Group 13 private key (attempt {attempt + 1}/"
                f"{max_attempts}): "
            )
            try:
                # Try unlocking the key
                key.unlock(password)
                print("✓ Private key unlocked successfully")
                # Store the password for later use
                key._stored_password = password  # Store password for reuse
                return key
            except Exception as e:
                print(f"❌ Failed to unlock key: {e}")
                if attempt == max_attempts - 1:
                    raise ValueError(
                        "Failed to unlock private key after maximum attempts"
                    ) from None
    else:
        print("✓ Private key is not password protected")
        key._stored_password = None

    return key


def create_rmap_message1(
    server_pub_key, nonce_client=12345678901234567890, identity="Group_13"
):
    """Create RMAP Message 1 encrypted with server's public key."""
    message1_data = {"nonceClient": nonce_client, "identity": identity}

    plaintext = json.dumps(message1_data)
    message = PGPMessage.new(plaintext)
    encrypted_message = server_pub_key.encrypt(message)

    armored = str(encrypted_message)
    payload_b64 = base64.b64encode(armored.encode("utf-8")).decode("utf-8")

    return {"payload": payload_b64}, nonce_client


def decrypt_server_response(encrypted_payload, group13_private_key):
    """Decrypt the server's response to extract nonceServer."""
    try:
        # Decode base64
        encrypted_armored = base64.b64decode(encrypted_payload).decode("utf-8")

        # Parse PGP message
        pgp_message = PGPMessage.from_blob(encrypted_armored)

        # If key is protected, use context manager for proper unlocking
        if group13_private_key.is_protected and hasattr(
            group13_private_key, "_stored_password"
        ):
            print("✓ Using stored password to decrypt server response")
            # Use context manager for proper key unlocking
            with group13_private_key.unlock(group13_private_key._stored_password):
                decrypted_message = group13_private_key.decrypt(pgp_message)
        else:
            # Decrypt with Group 13's private key (unprotected key)
            decrypted_message = group13_private_key.decrypt(pgp_message)

        # Parse JSON
        response_data = json.loads(decrypted_message.message)
        return response_data

    except Exception as e:
        print(f"Error decrypting server response: {e}")
        return None


def create_rmap_message2(server_pub_key, nonce_server):
    """Create RMAP Message 2 encrypted with server's public key."""
    message2_data = {"nonceServer": nonce_server}

    plaintext = json.dumps(message2_data)
    message = PGPMessage.new(plaintext)
    encrypted_message = server_pub_key.encrypt(message)

    armored = str(encrypted_message)
    payload_b64 = base64.b64encode(armored.encode("utf-8")).decode("utf-8")

    return {"payload": payload_b64}


def test_dynamic_rmap_flow():
    """Test complete RMAP flow with dynamic Message 2 generation."""
    print("Dynamic RMAP Test")
    print("=" * 50)

    try:
        # Load keys
        print("Loading keys...")
        server_pub_key = load_server_public_key()
        print(f"✓ Loaded server public key: {server_pub_key.fingerprint}")

        group13_private_key = load_group13_private_key()
        print(f"✓ Loaded Group 13 private key: {group13_private_key.fingerprint}")

        # Step 1: Create and send Message 1
        print("\nStep 1: Creating and sending RMAP Message 1...")
        msg1_payload, nonce_client = create_rmap_message1(server_pub_key)
        print(f"✓ Created Message 1 with client nonce: {nonce_client}")

        response1 = requests.post(
            f"{SERVER_URL}/api/rmap-initiate", json=msg1_payload, timeout=10
        )
        if response1.status_code != 200:
            print(f"❌ Message 1 failed: {response1.text}")
            return False

        response1_data = response1.json()
        print("✓ Message 1 sent successfully")
        print(
            f"Server response payload length: {len(response1_data.get('payload', ''))}"
        )

        # Step 2: Decrypt server response to get nonceServer
        print("\nStep 2: Decrypting server response...")
        print(f"Raw server response: {response1_data}")

        # Show the base64 payload for debugging
        if "payload" in response1_data:
            print(f"Base64 payload preview: {response1_data['payload'][:100]}...")

        server_response_decrypted = decrypt_server_response(
            response1_data["payload"], group13_private_key
        )

        if not server_response_decrypted:
            print("❌ Failed to decrypt server response")
            print("Server response details:")
            print(f"  Status code: {response1.status_code}")
            print(f"  Headers: {dict(response1.headers)}")
            print(f"  Response body: {response1_data}")
            return False

        print(f"✓ Decrypted server response: {server_response_decrypted}")

        if "nonceServer" not in server_response_decrypted:
            print("❌ nonceServer not found in server response")
            return False

        nonce_server = server_response_decrypted["nonceServer"]
        print(f"✓ Extracted server nonce: {nonce_server}")

        # Step 3: Create and send Message 2
        print("\nStep 3: Creating and sending RMAP Message 2...")
        msg2_payload = create_rmap_message2(server_pub_key, nonce_server)
        print("✓ Created Message 2 with server nonce")

        response2 = requests.post(
            f"{SERVER_URL}/api/rmap-get-link", json=msg2_payload, timeout=10
        )
        if response2.status_code != 200:
            print(f"❌ Message 2 failed: {response2.text}")
            return False

        response2_data = response2.json()
        print("✓ Message 2 sent successfully")
        print(f"Final result: {response2_data}")

        # Verify the result
        if "result" in response2_data:
            session_secret = response2_data["result"]
            print("✓ RMAP flow completed successfully!")
            print(f"Session secret: {session_secret}")

            # Calculate expected result for verification
            combined = (int(nonce_client) << 64) | int(nonce_server)
            expected_hex = f"{combined:032x}"

            if session_secret == expected_hex:
                print("✓ Session secret matches expected value")
            else:
                print(f"⚠ Session secret mismatch. Expected: {expected_hex}")

            return True
        else:
            print(f"❌ No result in final response: {response2_data}")
            return False

    except Exception as e:
        print(f"❌ Error during RMAP flow: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run the dynamic RMAP test."""
    success = test_dynamic_rmap_flow()
    print(f"\n{'✓ SUCCESS' if success else '❌ FAILED'}")
    return success


if __name__ == "__main__":
    import sys

    success = main()
    sys.exit(0 if success else 1)
