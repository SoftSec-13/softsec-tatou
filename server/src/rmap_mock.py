"""
Mock RMAP implementation for testing purposes.

This implements the same interface as the real RMAP library but without
the PGP dependencies, suitable for development and testing environments.
"""

import base64
import json
import secrets
from dataclasses import dataclass, field


class RMAPError(Exception):
    """Base error for RMAP."""


class ValidationError(RMAPError):
    """Raised when an incoming message is malformed."""


class DecryptionError(RMAPError):
    """Raised when a payload cannot be decrypted."""


class EncryptionError(RMAPError):
    """Raised when a payload cannot be encrypted."""


class UnknownIdentityError(RMAPError):
    """Raised when an operation references an unknown identity."""


def _is_u64(n: int) -> bool:
    return isinstance(n, int) and 0 <= n <= (2**64 - 1)


@dataclass
class MockIdentityManager:
    """Mock identity manager that simulates PGP operations."""

    # For testing, we'll accept a hardcoded set of identities
    known_identities: dict[str, bool] = field(
        default_factory=lambda: {"Jean": True, "Alice": True, "Bob": True}
    )

    def has_identity(self, identity: str) -> bool:
        """Check whether a public key for the given identity is loaded."""
        return identity in self.known_identities

    def decrypt_for_server(self, payload_b64: str) -> dict:
        """
        Mock decrypt - simply decodes the base64 payload and parses as JSON.
        In real implementation this would use PGP decryption.
        """
        try:
            # For mock purposes, we assume the payload is just base64-encoded JSON
            decoded_bytes = base64.b64decode(payload_b64, validate=True)
            plaintext = decoded_bytes.decode("utf-8")
            return json.loads(plaintext)
        except Exception as exc:
            raise DecryptionError(f"Mock decryption failed: {exc}") from exc

    def encrypt_for_identity(self, identity: str, payload_obj: dict) -> str:
        """
        Mock encrypt - simply encodes the JSON as base64.
        In real implementation this would use PGP encryption.
        """
        if not self.has_identity(identity):
            raise UnknownIdentityError(f"Unknown identity: {identity}")

        try:
            plaintext = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True)
            encoded_bytes = base64.b64encode(plaintext.encode("utf-8"))
            return encoded_bytes.decode("ascii")
        except Exception as exc:
            raise EncryptionError(
                f"Mock encryption failed for identity '{identity}': {exc}"
            ) from exc


@dataclass
class MockRMAP:
    """
    Mock RMAP server-side protocol logic.

    This simulates the same interface as the real RMAP class but without PGP
    dependencies.
    """

    identity_manager: MockIdentityManager
    nonces: dict[str, tuple[int, int]] = field(default_factory=dict)

    def handle_message1(self, incoming: dict) -> dict:
        """
        Process Message 1 and return Response 1.

        Returns a dict either of shape:
          {"payload": "<base64-asc-pgp>"}  on success
        or {"error": "<reason>"}          on failure
        """
        try:
            payload_b64 = self._extract_payload(incoming)
            obj = self.identity_manager.decrypt_for_server(payload_b64)
            identity, nonce_client = self._parse_msg1(obj)

            if not self.identity_manager.has_identity(identity):
                raise UnknownIdentityError(f"Unknown identity: {identity}")

            # Generate server nonce (u64)
            nonce_server = secrets.randbits(64)

            # Save/overwrite state for this identity
            self.nonces[identity] = (nonce_client, nonce_server)

            # Prepare response object and encrypt to the client's public key
            resp_obj = {"nonceClient": nonce_client, "nonceServer": nonce_server}
            payload_out = self.identity_manager.encrypt_for_identity(identity, resp_obj)
            return {"payload": payload_out}

        except (
            ValidationError,
            DecryptionError,
            EncryptionError,
            UnknownIdentityError,
        ) as exc:
            return {"error": str(exc)}
        except Exception as exc:  # safety net
            return {"error": f"Unhandled error in handle_message1: {exc}"}

    def handle_message2(self, incoming: dict) -> dict:
        """
        Process Message 2 and return the final result.

        Returns a dict either of shape:
          {"result": "<hex>"}             on success
        or {"error": "<reason>"}          on failure
        """
        try:
            payload_b64 = self._extract_payload(incoming)
            obj = self.identity_manager.decrypt_for_server(payload_b64)
            nonce_server = self._parse_msg2(obj)

            # Find which identity stored this nonceServer
            identity = self._find_identity_by_nonce_server(nonce_server)
            if identity is None:
                raise ValidationError("nonceServer does not match any pending session")

            nonce_client, stored_nonce_server = self.nonces[identity]
            if stored_nonce_server != nonce_server:
                # Extremely defensive check (shouldn't happen if lookup succeeded)
                raise ValidationError("nonceServer mismatch for resolved identity")

            # Concatenate as 128-bit value: NonceClient || NonceServer (big-endian)
            combined = (int(nonce_client) << 64) | int(nonce_server)
            # Produce zero-padded 32-hex-digit string (128 bits)
            hex_str = f"{combined:032x}"

            return {"result": hex_str}

        except (ValidationError, DecryptionError) as exc:
            return {"error": str(exc)}
        except Exception as exc:  # safety net
            return {"error": f"Unhandled error in handle_message2: {exc}"}

    @staticmethod
    def _extract_payload(incoming: dict) -> str:
        if not isinstance(incoming, dict):
            raise ValidationError("Incoming message must be a JSON object")
        if "payload" not in incoming:
            raise ValidationError("Missing 'payload' field")
        payload = incoming["payload"]
        if not isinstance(payload, str) or not payload:
            raise ValidationError("'payload' must be a non-empty base64 string")
        return payload

    @staticmethod
    def _parse_msg1(obj: dict) -> tuple[str, int]:
        if not isinstance(obj, dict):
            raise ValidationError("Decrypted payload must be a JSON object")
        if "identity" not in obj or "nonceClient" not in obj:
            raise ValidationError("Message 1 must contain 'identity' and 'nonceClient'")
        identity = obj["identity"]
        nonce_client = obj["nonceClient"]
        if not isinstance(identity, str) or not identity:
            raise ValidationError("'identity' must be a non-empty string")
        if not _is_u64(nonce_client):
            raise ValidationError("'nonceClient' must be a 64-bit unsigned integer")
        return identity, int(nonce_client)

    @staticmethod
    def _parse_msg2(obj: dict) -> int:
        if not isinstance(obj, dict):
            raise ValidationError("Decrypted payload must be a JSON object")
        if "nonceServer" not in obj:
            raise ValidationError("Message 2 must contain 'nonceServer'")
        nonce_server = obj["nonceServer"]
        if not _is_u64(nonce_server):
            raise ValidationError("'nonceServer' must be a 64-bit unsigned integer")
        return int(nonce_server)

    def _find_identity_by_nonce_server(self, nonce_server: int) -> str | None:
        for ident, (_nc, ns) in self.nonces.items():
            if ns == nonce_server:
                return ident
        return None


# Create global instances for the server to use
_identity_manager = MockIdentityManager()
_rmap = MockRMAP(_identity_manager)


def get_rmap_instance():
    """Get the global RMAP instance."""
    return _rmap
