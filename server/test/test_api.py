import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from server import create_app


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


def test_healthz_route(client):
    """Test the health check endpoint."""
    resp = client.get("/healthz")

    assert resp.status_code == 200  # nosec B101
    assert resp.is_json  # nosec B101


def test_create_user_route(client):
    """Test user creation endpoint."""
    parameters = {
        "login": "username",
        "password": "password",
        "email": "user@email.se",
    }  # pragma: allowlist secret
    resp = client.post("/api/create-user", json=parameters)

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    #basic tests
    assert resp.status_code == 201  # Endpoint should exist
    assert resp.is_json
    #check types
    assert isinstance(resp.get("id"), int)
    assert isinstance(resp.get("login"), str) 
    assert isinstance(resp.get("email"), str)
    #check values are what we submitted
    assert resp.get("login") == parameters["login"]
    assert resp.get("email") == parameters["email"]


def test_login_route(client):
    """Test login endpoint."""
    parameters = {
        "email": "user@email.se",
        "password": "password",
    }  # pragma: allowlist secret
    resp = client.post("/api/login", json=parameters)

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    assert isinstance(resp.get("token"), str) 
    assert isinstance(resp.get("token_type"), str)
    assert isinstance(resp.get("expires_in"), int)
    #check val
    assert resp.get("token_type") == "bearer"



def test_upload_document_route(client):
    """Test document upload endpoint."""
    # This endpoint might be commented out in the current server implementation
    # Let's test if it exists
    pdf_file = "" #TODO add dummy file for testing
    parameters = {"file":pdf_file, "name":"My File"}
    resp = client.post("/api/upload-document", json=parameters)

    # Should return 404 if route is commented out, or other error if route exists
    #assert resp.status_code in [404, 400, 405, 500]  # Various expected error codes

    #tests when fully functional
    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    assert isinstance(resp.get("id"), str) 
    assert isinstance(resp.get("name"), str) 
    assert isinstance(resp.get("creation"), str) and datetime.fromisoformat(resp.get("creation"))
    assert isinstance(resp.get("sha256"), str) 
    assert isinstance(resp.get("size"), int) 
    #check value
    assert resp.get("name") == parameters["name"]
