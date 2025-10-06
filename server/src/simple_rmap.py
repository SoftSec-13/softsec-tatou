"""
RMAP (Roger Michael Authentication Protocol) implementation for Tatou.

Uses the proper RMAP library for cryptographic authentication between
clients and server.

This implementation includes identity extraction to capture the group name
from RMAP Message 1 and use it as the 'intended_for' field in database entries.
"""

import base64
import json
import os
from pathlib import Path
from typing import Any

from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

try:
    from pgpy import PGPKey, PGPMessage

    PGP_AVAILABLE = True
except ImportError:
    PGP_AVAILABLE = False


class SimpleRMAP:
    """RMAP implementation using the proper RMAP library."""

    def __init__(
        self,
        storage_dir: str,
        public_keys_dir: str | None = None,
        server_private_key: str | None = None,
    ):
        self.storage_dir = storage_dir
        self.watermarked_pdfs: dict[
            str, dict[str, Any]
        ] = {}  # Store metadata about watermarked PDFs
        self.session_identities: dict[
            str, str
        ] = {}  # Store identity for each session secret
        self.pending_identities: dict[
            int, str
        ] = {}  # Store identity for each nonce_client during handshake

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
            server_private_key_path=server_private_key,
            server_private_key_passphrase=os.getenv("PRIVKEY_PASSPHRASE", ""),
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

            # Try to extract identity from the payload before processing
            identity_data = self._decrypt_message1_payload(incoming["payload"])
            if identity_data:
                nonce_client = identity_data.get("nonceClient")
                identity = identity_data.get("identity", "Unknown_Group")
                if nonce_client is not None:
                    # Store identity for later correlation with session secret
                    self.pending_identities[nonce_client] = identity

            # Use RMAP library to handle message 1
            result = self.rmap.handle_message1(incoming)

            return result

        except Exception as e:
            return {"error": f"RMAP processing error: {str(e)}"}

    def _decrypt_message1_payload(self, payload: str) -> dict[str, Any] | None:
        """
        Decrypt message 1 payload to extract identity and nonce_client.
        This allows us to capture the identity before passing to RMAP library.
        """
        if not PGP_AVAILABLE:
            return None

        try:
            # Load server private key for decryption
            server_private_key_path = str(Path(__file__).parent / "server_priv.asc")
            if not Path(server_private_key_path).exists():
                return None

            # Load the private key
            server_key, _ = PGPKey.from_file(server_private_key_path)

            # Unlock the private key if it's protected
            if server_key.is_protected:
                passphrase = os.getenv("PRIVKEY_PASSPHRASE", "")
                if not passphrase:
                    return None
                server_key.unlock(passphrase)

            # Decode the base64 payload
            encrypted_armored = base64.b64decode(payload).decode("utf-8")

            # Parse the PGP message
            pgp_message = PGPMessage.from_blob(encrypted_armored)

            # Decrypt the message
            decrypted_message = server_key.decrypt(pgp_message)

            # Parse the JSON content
            message_data = json.loads(decrypted_message.message)

            return message_data

        except Exception:
            return None

    def handle_message2(self, incoming: dict[str, Any]) -> dict[str, Any]:
        """
        Handle second RMAP message (rmap-get-link).

        Expected incoming: {"payload": "<base64(ASCII-armored PGP)>"}
        Expected decrypted content: {"nonceServer": <u64>}

        Returns: {"result": "<32-hex>"} or {"error": "<reason>"}
        where result is the session secret (32 hex chars) used as link to
        watermarked PDF.
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

                # Try to correlate with pending identity
                # The session secret is (nonce_client << 64) | nonce_server
                # We can try to find the matching identity
                identity = self._find_identity_for_session(session_secret)
                if identity:
                    self.session_identities[session_secret] = identity

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

    def _find_identity_for_session(self, session_secret: str) -> str | None:
        """
        Try to find the identity that corresponds to this session secret.
        This implements correlation between Message 1 and Message 2.
        """
        # For simple cases where there's only one pending identity,
        # use it (works for single concurrent session)
        if self.pending_identities:
            # Use the first available identity and clear it
            identity = next(iter(self.pending_identities.values()))
            # Clear pending identities since we've used them
            self.pending_identities.clear()
            return identity

        # Default fallback - better than hardcoded "RMAP_CLIENT"
        return "Unknown_Group"

    def get_watermarked_pdf_info(self, session_secret: str) -> dict[str, Any] | None:
        """Get watermarked PDF metadata for a session secret."""
        return self.watermarked_pdfs.get(session_secret)

    def get_session_identity(self, session_secret: str) -> str | None:
        """Get the identity (group name) for a session secret."""
        return self.session_identities.get(session_secret)

    def set_session_identity(self, session_secret: str, identity: str) -> None:
        """Set the identity (group name) for a session secret."""
        self.session_identities[session_secret] = identity

    def set_pending_identity(self, nonce_client: int, identity: str) -> None:
        """Set pending identity for a nonce_client (for testing/manual setup)."""
        self.pending_identities[nonce_client] = identity
