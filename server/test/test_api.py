import sys
from pathlib import Path
import json
from datetime import datetime
from io import BytesIO
from unittest.mock import patch
from flask import g, request

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from server import create_app

#TODO: Make requireauth always return true for testing!

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    app = create_app(testing=True)
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
    resp_data = resp.get_json()

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    #basic tests
    assert resp.status_code == 201  # Endpoint should exist
    assert resp.is_json
    #check types
    assert isinstance(resp_data.get("id"), int)
    assert isinstance(resp_data.get("login"), str) 
    assert isinstance(resp_data.get("email"), str)
    #check values are what we submitted
    assert resp_data.get("login") == parameters["login"]
    assert resp_data.get("email") == parameters["email"]


def test_login_route(client):
    """Test login endpoint."""
    parameters = {
        "email": "user@email.se",
        "password": "password",
    }  # pragma: allowlist secret
    resp = client.post("/api/login", json=parameters)
    resp_data = resp.get_json()

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    assert isinstance(resp_data.get("token"), str) 
    assert isinstance(resp_data.get("token_type"), str)
    assert isinstance(resp_data.get("expires_in"), int)
    #check val
    assert resp_data.get("token_type") == "bearer"


def test_upload_document_route(client):
    """Test document upload endpoint."""
    # This endpoint might be commented out in the current server implementation
    # Let's test if it exists
    #create dummy file
    pdf_file = (BytesIO(b"%PDF-1.4 dummy pdf content"), "test_document.pdf")
    #parameters = {"file":pdf_file, "name":"My File"}
    parameters = {
    "file": (BytesIO(b"%PDF-1.4 dummy pdf content"), "test_document.pdf"),
    "name": "My File",
    }
    resp = client.post("/api/upload-document", data=parameters, content_type='multipart/form-data')
    resp_data = resp.get_json()

    # Should return 404 if route is commented out, or other error if route exists
    #assert resp.status_code in [404, 400, 405, 500]  # Various expected error codes

    #tests when fully functional
    #basic tests
    assert resp.status_code == 201
    assert resp.is_json
    #check types
    assert isinstance(resp_data.get("id"), int) #was string! Specification is wrong.
    assert isinstance(resp_data.get("name"), str) 
    assert isinstance(resp_data.get("creation"), str) and datetime.fromisoformat(resp_data.get("creation"))
    assert isinstance(resp_data.get("sha256"), str) 
    assert isinstance(resp_data.get("size"), int) 
    #check value
    assert resp_data.get("name") == parameters["name"]

def test_list_documents_route(client):
    """Test document list endpoint."""
    resp = client.get("/api/list-documents")
    resp_data = resp.get_json()

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    #extract data
    doc_list = resp_data.get("documents")
    assert isinstance(doc_list, list)
    #cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), int) #was string! Specification is wrong.
        assert isinstance(elem.get("name"), str) 
        assert isinstance(elem.get("creation"), str) and datetime.fromisoformat(elem.get("creation"))
        assert isinstance(elem.get("sha256"), str) 
        assert isinstance(elem.get("size"), int)

def test_list_versions_route(client):
    """Test list versions endpoint."""
    parameters = {"documentid":1}
    resp = client.get("/api/list-versions", query_string = parameters) 
    #resp = client.get("/api/list-versions/1") #for test without parameters
    resp_data = resp.get_json()

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    #extract data
    doc_list = resp_data.get("versions")
    assert isinstance(doc_list, list)
    #cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), str) 
        assert isinstance(elem.get("documentid"), str) 
        #check the version is from the correct document
        assert elem.get("documentid") == str(parameters["documentid"])
        assert isinstance(elem.get("link"), str) 
        assert isinstance(elem.get("intended_for"), str) 
        assert isinstance(elem.get("secret"), str) 
        assert isinstance(elem.get("method"), str) 


def test_list_all_versions_route(client):
    """Test list all versions endpoint."""
    #call without parameters
    resp = client.get("/api/list-all-versions") #Fix list all versions on API.md!
    resp_data = resp.get_json()

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    #extract data
    doc_list = resp_data.get("versions")
    assert isinstance(doc_list, list)
    #cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), str) 
        assert isinstance(elem.get("documentid"), str) 
        assert isinstance(elem.get("link"), str) 
        assert isinstance(elem.get("intended_for"), str) 
        assert isinstance(elem.get("secret"), str) 
        assert isinstance(elem.get("method"), str) 

def test_get_document_route(client):
    """Test get document endpoint."""
    parameters = {"documentid":1}
    resp = client.get("/api/get-document", query_string=parameters)
    #resp = client.get("/api/get-document/1") #for test without parameters

    # Check Content-Type
    is_pdf = resp.headers.get('Content-Type') == 'application/pdf'
    # Check Content-Disposition for 'inline'
    content_disposition = resp.headers.get('Content-Disposition', '')
    is_inline = 'inline' in content_disposition.lower()
    # Check if the body starts with PDF signature
    #is_binary_pdf = resp.content.startswith(b'%PDF-')
    #Oracle
    assert is_pdf
    assert is_inline
    #assert is_binary_pdf

def test_get_watermarking_methods_route(client):
    """Test get watermarking methods endpoint."""
    resp = client.get("/api/get-watermarking-methods")
    data = resp.get_json()

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    assert isinstance(data.get("count"), int)
    methods = data.get("methods")
    assert isinstance(methods, list)
    for i in range (0, data.get("count")):
        assert isinstance(methods[i].get("description"), str)
        assert isinstance(methods[i].get("name"), str)

def test_create_watermark_route(client):
        """Test create watermark endpoint."""
        parameters = {"method": "robust-xmp", "position": "metadata-only", "key": "key", 
                    "secret": "secret", "intended_for":"Mickey Mouse", "id": 1}
        parameters_no_id = {"method": "robust-xmp", "position": "metadata-only", "key": "key", "secret": "secret", "intended_for":"Mickey Mouse"}
        resp = client.post("/api/create-watermark", json=parameters)
        #resp = client.post("/apicreate-watermark/1", json=parameters_no_id)
        data = resp.get_json()

        #basic tests
        assert resp.status_code == 201
        assert resp.is_json
        #check types
        assert isinstance(data.get("id"), int)
        assert isinstance(data.get("documentid"), int)
        assert isinstance(data.get("link"), str)
        assert isinstance(data.get("intended_for"), str)
        assert isinstance(data.get("method"), str)
        assert isinstance(data.get("position"), str)
        assert isinstance(data.get("filename"), str)
        assert isinstance(data.get("size"), int)
        #check values
        assert data.get("documentid") == parameters["id"]
        assert data.get("intended_for") == parameters["intended_for"]
        assert data.get("method") == parameters["method"]
        assert data.get("position") == parameters["position"]

def test_read_watermark_route(client):
    """Test read watermark endpoint."""
    #Upload watermarked file to the app
    with open("storage\\files\\username\\watermarked.pdf", "rb") as f:
        data = {
            "file": (f, "watermarked.pdf"),
            "name": "Water File"
        }
        upload_resp = client.post("/api/upload-document", data=data, content_type='multipart/form-data')
        upload_resp_data = upload_resp.get_json()
        assert upload_resp.status_code == 201
        assert upload_resp_data.get("id") == 2
    #Test the route

    parameters = {"method": "overlay-watermark", "position": "metadata-only", "key": "strong-password", "id": 2}
    parameters_no_id = {"method": "overlay-watermark", "position": "metadata-only", "key": "strong-password"}
    resp = client.post("/api/read-watermark", json=parameters)
    #resp = client.post("/api/read-watermark/2", json=parameters_no_id)
    data = resp.get_json()

    #basic tests
    assert resp.status_code == 201
    assert resp.is_json
    #check types
    assert isinstance(data.get("documentid"), int)
    assert isinstance(data.get("secret"), str)
    assert isinstance(data.get("method"), str)
    assert isinstance(data.get("position"), str)
    #check values
    assert data.get("documentid") == parameters["id"]
    assert data.get("method") == parameters["method"]
    assert data.get("position") == parameters["position"]

