#!/usr/bin/env python3
"""
Script to generate OpenPGP key pairs for RMAP authentication using Python
cryptography library. This creates server keys and sample client keys for
testing without requiring GPG.
"""

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_key_pair(key_size=2048):
    """Generate an RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def create_pgp_armor(key_bytes, key_type="PUBLIC KEY"):
    """Create ASCII armored PGP format"""
    encoded = base64.b64encode(key_bytes).decode("ascii")

    # Break into 64-character lines
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]

    armor = f"-----BEGIN PGP {key_type} BLOCK-----\n"
    armor += "Version: Python-Generated\n\n"
    armor += "\n".join(lines)
    armor += f"\n-----END PGP {key_type} BLOCK-----\n"

    return armor


def create_simple_keys():
    """Create simplified key files that work with the RMAP library"""

    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Create client_keys directory if it doesn't exist
    client_keys_dir = Path("client_keys")
    client_keys_dir.mkdir(exist_ok=True)

    print("RMAP Key Generation Script (Python-based)")
    print("=" * 50)

    # Generate server key pair
    print("Generating server key pair...")
    server_private, server_public = generate_rsa_key_pair()

    # Serialize server keys
    server_private_pem = server_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    server_public_pem = server_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create PGP-like format for compatibility
    server_pub_armor = create_pgp_armor(server_public_pem, "PUBLIC KEY")
    server_priv_armor = create_pgp_armor(server_private_pem, "PRIVATE KEY")

    # Write server keys
    with open("server_pub.asc", "w") as f:
        f.write(server_pub_armor)

    with open("server_priv.asc", "w") as f:
        f.write(server_priv_armor)

    print("✓ Server keys generated")

    # Generate sample client keys for testing
    test_groups = [
        "Group1",
        "Group7",
        "TestClient",
    ]

    for group_name in test_groups:
        print(f"Generating key pair for {group_name}...")

        client_private, client_public = generate_rsa_key_pair()

        # Serialize client keys
        client_private_pem = client_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        client_public_pem = client_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create PGP-like format
        client_pub_armor = create_pgp_armor(client_public_pem, "PUBLIC KEY")
        client_priv_armor = create_pgp_armor(client_private_pem, "PRIVATE KEY")

        # Write client keys
        client_pub_file = client_keys_dir / f"{group_name}.asc"
        client_priv_file = client_keys_dir / f"{group_name}_priv.asc"

        with open(client_pub_file, "w") as f:
            f.write(client_pub_armor)

        with open(client_priv_file, "w") as f:
            f.write(client_priv_armor)

        print(f"✓ {group_name} keys generated")

    print("\n" + "=" * 50)
    print("Key generation complete!")
    print("\nGenerated files:")
    print("- server_pub.asc (server public key)")
    print("- server_priv.asc (server private key) - KEEP SECURE!")

    for group_name in test_groups:
        print(f"- client_keys/{group_name}.asc (client public key)")
        print(f"- client_keys/{group_name}_priv.asc (client private key)")

    print("\nNOTE: These are PEM keys in PGP armor format for compatibility.")
    print("If the RMAP library requires true PGP format, you may need to use GPG.")

    return True


if __name__ == "__main__":
    try:
        create_simple_keys()
    except ImportError as e:
        print(f"Missing required library: {e}")
        print("Please install: pip install cryptography")
        exit(1)
    except Exception as e:
        print(f"Error generating keys: {e}")
        exit(1)
