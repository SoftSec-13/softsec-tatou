"""
RMAP (Roger Michael Authentication Protocol) implementation for Tatou.

Uses the proper RMAP library for cryptographic authentication between clients and server.
"""

import base64
from pathlib import Path
from typing import Any

from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP


class SimpleRMAP:
    """RMAP implementation using the proper RMAP library."""

    def __init__(self, storage_dir: str, public_keys_dir: str = None, server_private_key: str = None):
        self.storage_dir = storage_dir
        self.watermarked_pdfs: dict[str, dict[str, Any]] = {}  # Store metadata about watermarked PDFs

        # Set up paths for keys
        if public_keys_dir is None:
            # Default to public-keys/pki directory relative to server root
            server_root = Path(__file__).parent.parent
            public_keys_dir = str(server_root / "public-keys" / "pki")

        if server_private_key is None:
            # Default to server_priv.asc in src directory
            server_private_key = str(Path(__file__).parent / "server_priv.asc")

        # Server public key path (needed for IdentityManager)
        server_public_key = str(Path(__file__).parent / "server_pub.asc")

        # Initialize RMAP components with correct API
        self.identity_manager = IdentityManager(
            client_keys_dir=public_keys_dir,
            server_public_key_path=server_public_key,
            server_private_key_path=server_private_key
        )
        self.rmap = RMAP(self.identity_manager)

    def handle_message1(self, incoming: dict[str, Any]) -> dict[str, Any]:
        """
        Handle first RMAP message (rmap-initiate).

        Expected incoming: {"payload": "<base64(ASCII-armored PGP)>"}
        Expected decrypted content: {"nonceClient": <u64>, "identity": "<GroupName>"}

        Returns: {"payload": "<base64(encrypted_response)>"} or {"error": "<reason>"}
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}

            # Use RMAP library to handle message 1
            # The library expects the exact format we receive
            result = self.rmap.handle_message1(incoming)

            return result

        except Exception as e:
            return {"error": f"RMAP processing error: {str(e)}"}

    def handle_message2(self, incoming: dict[str, Any]) -> dict[str, Any]:
        """
        Handle second RMAP message (rmap-get-link).

        Expected incoming: {"payload": "<base64(ASCII-armored PGP)>"}
        Expected decrypted content: {"nonceServer": <u64>}

        Returns: {"result": "<32-hex>"} or {"error": "<reason>"}
        where result is the session secret (32 hex chars) used as link to watermarked PDF.
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}

            # Use RMAP library to handle message 2
            # The library will return {"result": "hex_string"} or {"error": "message"}
            result = self.rmap.handle_message2(incoming)

            if "result" in result:
                session_secret = result["result"]

                # Ensure it's a 32-character hex string
                if len(session_secret) < 32:
                    session_secret = session_secret.zfill(32)
                elif len(session_secret) > 32:
                    session_secret = session_secret[:32]

                # Store watermark metadata for this session
                self.watermarked_pdfs[session_secret] = {
                    "method": "robust-xmp",
                    "created": True,
                    "session_secret": session_secret,
                }

                return {"result": session_secret}

            return result

        except Exception as e:
            return {"error": f"RMAP processing error: {str(e)}"}

    def get_watermarked_pdf_info(self, session_secret: str) -> dict[str, Any] | None:
        """Get watermarked PDF metadata for a session secret."""
        return self.watermarked_pdfs.get(session_secret)
