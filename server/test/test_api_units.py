"""Unit tests for API endpoints that don't require database integration.

These tests focus on testing API endpoint logic, validation, and error handling
without requiring a running database connection.
"""

import sys
import tempfile
from pathlib import Path

import pytest

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server import create_app


class TestAPIUnits:
    """Unit tests for API endpoints with mocked dependencies."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        app = create_app()
        app.config.update(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",  # pragma: allowlist secret
                "TOKEN_TTL_SECONDS": 3600,
                "STORAGE_DIR": Path(tempfile.mkdtemp()),
            }
        )
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_healthz_endpoint_basic_structure(self, client):
        """Test /healthz endpoint basic response structure (without DB mocking)."""
        resp = client.get("/healthz")

        assert resp.status_code == 200
        assert resp.is_json

        data = resp.get_json()
        # According to API spec: "MUST always contain a 'message' field of type string"
        assert "message" in data
        assert isinstance(data["message"], str)
        assert data["message"] == "The server is up and running."

        # Should also include db_connected status (will be False without real DB)
        assert "db_connected" in data
        assert isinstance(data["db_connected"], bool)

    def test_healthz_no_auth_required(self, client):
        """Test that /healthz is accessible without authentication."""
        # Should work without any auth headers
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_create_user_validation_email_required(self, client):
        """Test user creation fails when email is missing."""
        user_data = {"login": "testuser", "password": "securepass123"}

        resp = client.post("/api/create-user", json=user_data)

        assert resp.status_code == 400
        assert resp.is_json

        data = resp.get_json()
        assert "error" in data
        assert "required" in data["error"].lower()

    def test_create_user_validation_login_required(self, client):
        """Test user creation fails when login is missing."""
        user_data = {"email": "test@example.com", "password": "securepass123"}

        resp = client.post("/api/create-user", json=user_data)

        assert resp.status_code == 400
        assert resp.is_json

        data = resp.get_json()
        assert "error" in data
        assert "required" in data["error"].lower()

    def test_create_user_validation_password_required(self, client):
        """Test user creation fails when password is missing."""
        user_data = {"email": "test@example.com", "login": "testuser"}

        resp = client.post("/api/create-user", json=user_data)

        assert resp.status_code == 400
        assert resp.is_json

        data = resp.get_json()
        assert "error" in data
        assert "required" in data["error"].lower()

    def test_login_validation_email_required(self, client):
        """Test login fails when email is missing."""
        resp = client.post("/api/login", json={"password": "test123"})

        assert resp.status_code == 400
        assert resp.is_json

        data = resp.get_json()
        assert "error" in data
        assert "required" in data["error"].lower()

    def test_login_validation_password_required(self, client):
        """Test login fails when password is missing."""
        resp = client.post("/api/login", json={"email": "test@example.com"})

        assert resp.status_code == 400
        assert resp.is_json

        data = resp.get_json()
        assert "error" in data
        assert "required" in data["error"].lower()

    def test_json_content_type(self, client):
        """Test that JSON endpoints return correct content-type."""
        resp = client.get("/healthz")
        assert resp.content_type.startswith("application/json")

    def test_invalid_json_handling(self, client):
        """Test API gracefully handles invalid JSON."""
        resp = client.post(
            "/api/create-user", data="invalid json{", content_type="application/json"
        )

        # Should handle gracefully without crashing
        assert resp.status_code == 400

        resp = client.post(
            "/api/login", data="invalid json{", content_type="application/json"
        )

        assert resp.status_code == 400

    def test_empty_json_handling(self, client):
        """Test API handles empty/null JSON payloads."""
        resp = client.post("/api/create-user", json=None)
        assert resp.status_code == 400

        resp = client.post("/api/login", json=None)
        assert resp.status_code == 400

    def test_static_file_routes(self, client):
        """Test static file serving functionality."""
        # Test home route
        resp = client.get("/")
        # Should attempt to serve index.html (might not exist in test)
        assert resp.status_code in [200, 404]

        # Test static file route
        resp = client.get("/nonexistent.html")
        # Should return 404 for non-existent files
        assert resp.status_code == 404
