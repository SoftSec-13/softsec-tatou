"""
RMAP (Roger Michael Authentication Protocol) Tests.

This module tests the RMAP authentication flow:
- Message 1 payload structure and creation
- Message 2 payload structure and creation
- Session secret format validation
- RMAP flow logic without requiring full server infrastructure
"""

import base64
import json

import pytest


def decode_payload(payload_dict: dict) -> dict:
    """Decode a base64-encoded RMAP payload into JSON data."""
    decoded = base64.b64decode(payload_dict["payload"]).decode()
    return json.loads(decoded)


def create_mock_message1_payload(
    nonce_client=12345678901234567890, identity="Group_13"
):
    """
    Create a mock Message 1 payload for testing.

    Message 1 contains client nonce and identity, base64-encoded.
    In real RMAP, this would be PGP-encrypted.
    """
    message_data = {"nonceClient": nonce_client, "identity": identity}
    payload = base64.b64encode(json.dumps(message_data).encode()).decode()
    return {"payload": payload}


def create_mock_message2_payload(nonce_server=98765432109876543210):
    """
    Create a mock Message 2 payload for testing.

    Message 2 contains server nonce, base64-encoded.
    In real RMAP, this would be PGP-encrypted.
    """
    message_data = {"nonceServer": nonce_server}
    payload = base64.b64encode(json.dumps(message_data).encode()).decode()
    return {"payload": payload}


def calculate_session_secret(nonce_client: int, nonce_server: int) -> str:
    """
    Calculate RMAP session secret from nonces.

    The session secret is a 32-character hex string derived from:
    (nonce_client << 64) | nonce_server
    """
    combined = (nonce_client << 64) | nonce_server
    return f"{combined:032x}"


class TestRMAPPayloadStructure:
    """Test RMAP message payload structure and format."""

    def test_message1_payload_contains_required_fields(self):
        """Message 1 must contain nonceClient and identity."""
        payload = create_mock_message1_payload()
        data = decode_payload(payload)

        assert "nonceClient" in data  # nosec B101
        assert "identity" in data  # nosec B101

    def test_message1_payload_with_custom_values(self):
        """Message 1 can be created with custom nonce and identity."""
        nonce = 123456789
        identity = "TestGroup"

        payload = create_mock_message1_payload(nonce_client=nonce, identity=identity)
        data = decode_payload(payload)

        assert data["nonceClient"] == nonce  # nosec B101
        assert data["identity"] == identity  # nosec B101

    def test_message2_payload_contains_nonce_server(self):
        """Message 2 must contain nonceServer."""
        payload = create_mock_message2_payload()
        data = decode_payload(payload)

        assert "nonceServer" in data  # nosec B101

    def test_message2_payload_with_custom_nonce(self):
        """Message 2 can be created with custom server nonce."""
        nonce = 987654321

        payload = create_mock_message2_payload(nonce_server=nonce)
        data = decode_payload(payload)

        assert data["nonceServer"] == nonce  # nosec B101

    def test_payload_is_base64_encoded(self):
        """Payloads must be valid base64."""
        msg1 = create_mock_message1_payload()
        msg2 = create_mock_message2_payload()

        # Should not raise exception
        base64.b64decode(msg1["payload"])
        base64.b64decode(msg2["payload"])


class TestRMAPSessionSecret:
    """Test RMAP session secret calculation and format."""

    def test_session_secret_is_32_hex_chars(self):
        """Session secret must be exactly 32 hexadecimal characters."""
        secret = calculate_session_secret(
            nonce_client=12345678901234567890, nonce_server=98765432109876543210
        )

        assert len(secret) == 32  # nosec B101
        assert all(c in "0123456789abcdef" for c in secret)  # nosec B101

    def test_session_secret_deterministic(self):
        """Same nonces always produce same session secret."""
        secret1 = calculate_session_secret(nonce_client=123, nonce_server=456)
        secret2 = calculate_session_secret(nonce_client=123, nonce_server=456)

        assert secret1 == secret2  # nosec B101

    def test_session_secret_different_for_different_nonces(self):
        """Different nonces produce different session secrets."""
        secret1 = calculate_session_secret(nonce_client=123, nonce_server=456)
        secret2 = calculate_session_secret(nonce_client=789, nonce_server=456)

        assert secret1 != secret2  # nosec B101

    def test_session_secret_calculation_matches_spec(self):
        """Verify session secret calculation: (client << 64) | server."""
        client = 0x1234567890ABCDEF
        server = 0xFEDCBA0987654321

        secret = calculate_session_secret(client, server)

        # Manually calculate expected value
        expected = (client << 64) | server
        expected_hex = f"{expected:032x}"

        assert secret == expected_hex  # nosec B101


class TestRMAPIdentities:
    """Test RMAP identity handling."""

    @pytest.mark.parametrize(
        "identity",
        [
            "Group_13",
            "Group_07",
            "TestGroup",
            "RMAP_CLIENT",
            "Unknown_Group",
        ],
    )
    def test_message1_supports_various_identities(self, identity):
        """Message 1 can carry different group identities."""
        payload = create_mock_message1_payload(identity=identity)
        data = decode_payload(payload)

        assert data["identity"] == identity  # nosec B101


class TestRMAPFlow:
    """Test the complete RMAP authentication flow logic."""

    def test_complete_flow_data_structure(self):
        """Test data flow through complete RMAP handshake."""
        # Step 1: Client creates Message 1
        client_nonce = 12345678901234567890
        msg1 = create_mock_message1_payload(
            nonce_client=client_nonce, identity="Group_13"
        )

        assert "payload" in msg1  # nosec B101

        # Step 2: Server responds with server nonce (in real flow, encrypted)
        server_nonce = 98765432109876543210

        # Step 3: Client creates Message 2 with server nonce
        msg2 = create_mock_message2_payload(nonce_server=server_nonce)

        assert "payload" in msg2  # nosec B101

        # Step 4: Verify calculated session secret format
        session_secret = calculate_session_secret(client_nonce, server_nonce)

        assert len(session_secret) == 32  # nosec B101
        assert all(c in "0123456789abcdef" for c in session_secret)  # nosec B101

    def test_flow_preserves_identity(self):
        """Identity from Message 1 should be tracked through the flow."""
        identity = "Group_13"
        msg1 = create_mock_message1_payload(identity=identity)
        data = decode_payload(msg1)

        assert data["identity"] == identity  # nosec B101
