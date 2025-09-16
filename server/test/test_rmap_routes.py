"""Tests for RMAP routes."""

import base64
import json

from server import app


class TestRMAPRoutes:
    """Test RMAP authentication routes."""

    def test_rmap_initiate_missing_payload(self):
        """Test /rmap-initiate with missing payload returns 400."""
        client = app.test_client()
        resp = client.post("/rmap-initiate", json={}, content_type="application/json")

        assert resp.status_code == 400  # nosec B101
        assert resp.is_json  # nosec B101
        data = resp.get_json()
        assert data["error"] == "payload is required"  # nosec B101

    def test_rmap_get_link_missing_payload(self):
        """Test /rmap-get-link with missing payload returns 400."""
        client = app.test_client()
        resp = client.post("/rmap-get-link", json={}, content_type="application/json")

        assert resp.status_code == 400  # nosec B101
        assert resp.is_json  # nosec B101
        data = resp.get_json()
        assert data["error"] == "payload is required"  # nosec B101

    def test_rmap_initiate_with_valid_payload(self):
        """Test /rmap-initiate with valid RMAP Message 1."""
        client = app.test_client()

        # Create a mock Message 1: {"nonceClient": 123456, "identity": "Jean"}
        msg1 = {"nonceClient": 123456, "identity": "Jean"}
        msg1_json = json.dumps(msg1, separators=(",", ":"), sort_keys=True)
        # Mock "encrypt" by base64 encoding the JSON
        payload = base64.b64encode(msg1_json.encode("utf-8")).decode("ascii")

        resp = client.post(
            "/rmap-initiate", json={"payload": payload}, content_type="application/json"
        )

        assert resp.status_code == 200  # nosec B101
        assert resp.is_json  # nosec B101
        data = resp.get_json()
        assert "payload" in data  # nosec B101

        # Decode the response payload to verify it contains the expected nonces
        response_payload = base64.b64decode(data["payload"]).decode("utf-8")
        response_data = json.loads(response_payload)
        assert "nonceClient" in response_data  # nosec B101
        assert "nonceServer" in response_data  # nosec B101
        assert response_data["nonceClient"] == 123456  # nosec B101

    def test_rmap_get_link_with_valid_payload(self):
        """Test full RMAP flow: initiate then get-link."""
        client = app.test_client()

        # Step 1: Send Message 1
        msg1 = {"nonceClient": 654321, "identity": "Alice"}
        msg1_json = json.dumps(msg1, separators=(",", ":"), sort_keys=True)
        payload1 = base64.b64encode(msg1_json.encode("utf-8")).decode("ascii")

        resp1 = client.post(
            "/rmap-initiate",
            json={"payload": payload1},
            content_type="application/json",
        )

        assert resp1.status_code == 200  # nosec B101
        data1 = resp1.get_json()

        # Decode response to get the server nonce
        response_payload = base64.b64decode(data1["payload"]).decode("utf-8")
        response_data = json.loads(response_payload)
        nonce_server = response_data["nonceServer"]

        # Step 2: Send Message 2
        msg2 = {"nonceServer": nonce_server}
        msg2_json = json.dumps(msg2, separators=(",", ":"), sort_keys=True)
        payload2 = base64.b64encode(msg2_json.encode("utf-8")).decode("ascii")

        resp2 = client.post(
            "/rmap-get-link",
            json={"payload": payload2},
            content_type="application/json",
        )

        assert resp2.status_code == 200  # nosec B101
        assert resp2.is_json  # nosec B101
        data2 = resp2.get_json()
        assert "result" in data2  # nosec B101

        # Verify the result is a 32-character hex string (128 bits)
        result = data2["result"]
        assert len(result) == 32  # nosec B101
        assert all(c in "0123456789abcdef" for c in result)  # nosec B101

    def test_rmap_initiate_unknown_identity(self):
        """Test /rmap-initiate with unknown identity returns error."""
        client = app.test_client()

        # Create Message 1 with unknown identity
        msg1 = {"nonceClient": 789012, "identity": "UnknownUser"}
        msg1_json = json.dumps(msg1, separators=(",", ":"), sort_keys=True)
        payload = base64.b64encode(msg1_json.encode("utf-8")).decode("ascii")

        resp = client.post(
            "/rmap-initiate", json={"payload": payload}, content_type="application/json"
        )

        assert resp.status_code == 400  # nosec B101
        assert resp.is_json  # nosec B101
        data = resp.get_json()
        assert "error" in data  # nosec B101
        assert "Unknown identity" in data["error"]  # nosec B101

    def test_rmap_get_link_invalid_nonce(self):
        """Test /rmap-get-link with invalid nonce returns error."""
        client = app.test_client()

        # Send Message 2 with non-existent server nonce
        msg2 = {"nonceServer": 999999999}
        msg2_json = json.dumps(msg2, separators=(",", ":"), sort_keys=True)
        payload = base64.b64encode(msg2_json.encode("utf-8")).decode("ascii")

        resp = client.post(
            "/rmap-get-link", json={"payload": payload}, content_type="application/json"
        )

        assert resp.status_code == 400  # nosec B101
        assert resp.is_json  # nosec B101
        data = resp.get_json()
        assert "error" in data  # nosec B101
        assert "does not match any pending session" in data["error"]  # nosec B101

    def test_rmap_routes_exist(self):
        """Test that RMAP routes are accessible."""
        client = app.test_client()

        # Test that routes respond (not 404)
        resp1 = client.post("/rmap-initiate")
        assert resp1.status_code != 404  # nosec B101

        resp2 = client.post("/rmap-get-link")
        assert resp2.status_code != 404  # nosec B101
