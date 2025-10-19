import base64
import json
import os
import subprocess  # nosec: usage audited and controlled
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from time import sleep
from unittest.mock import PropertyMock, patch

import pgpy
import pytest
from dotenv import load_dotenv
from werkzeug.datastructures import FileStorage

from server import create_app

# Allow configuration to be set from evironment file
load_dotenv()

# Run environment preparation file
print("Preparing the environment...")
script_dir = Path(__file__).parent
env_script = script_dir / "prepare_env.bat"
result = subprocess.run(  # noqa: S603 # nosec prepping environ
    [str(env_script.resolve())]
)
print("Waiting for db to be ready...")
sleep(10)

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


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


# Global variable for document link to test get-version
@pytest.fixture(scope="module")
def shared_link():
    return {}


def test_healthz_route(client):
    """Test the health check endpoint."""
    resp = client.get("/healthz")

    assert resp.status_code == 200  # nosec B101
    assert resp.is_json  # nosec B101


def test_create_user_route(client):
    """Test user creation endpoint."""
    parameters = {
        "login": "username",
        "password": "password",  # nosec B106
        "email": "user@email.se",
    }
    resp = client.post("/api/create-user", json=parameters)
    resp_data = resp.get_json()

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    # basic tests
    assert resp.status_code == 201  # Endpoint should exist
    assert resp.is_json
    # check types
    assert isinstance(resp_data.get("id"), int)
    assert isinstance(resp_data.get("login"), str)
    assert isinstance(resp_data.get("email"), str)
    # check values are what we submitted
    assert resp_data.get("login") == parameters["login"]
    assert resp_data.get("email") == parameters["email"]

    # Test with missing parameters
    # Missing email
    resp = client.post(
        "/api/create-user",
        json={
            "login": "username",
            "password": "password",  # nosec B106
        },
    )
    assert resp.status_code == 400

    # Missing login
    resp = client.post(
        "/api/create-user",
        json={"email": "user@email.se", "password": "password"},
    )
    assert resp.status_code == 400

    # Missing password
    resp = client.post(
        "/api/create-user", json={"email": "user@email.se", "login": "username"}
    )
    assert resp.status_code == 400

    # Malformed email
    resp = client.post(
        "/api/create-user",
        json={
            "email": "malformedemail",
            "login": "username",
            "password": "password",  # nosec B106
        },
    )
    assert resp.status_code == 400


def test_login_route(client):
    """Test login endpoint."""
    parameters = {
        "email": "user@email.se",
        "password": "password",  # nosec B106
    }
    resp = client.post("/api/login", json=parameters)
    resp_data = resp.get_json()

    # Note: This will likely fail due to database connectivity in tests
    # but we can test that the endpoint exists and handles the request
    # basic tests
    assert resp.status_code == 200
    assert resp.is_json
    # check types
    assert isinstance(resp_data.get("token"), str)
    assert isinstance(resp_data.get("token_type"), str)
    assert isinstance(resp_data.get("expires_in"), int)
    # check val
    assert resp_data.get("token_type") == "bearer"

    # Test with missing parameters
    # Missing email
    resp = client.post("/api/login", json={"password": "password"})
    assert resp.status_code == 400
    # Missing password
    resp = client.post("/api/login", json={"email": "user@email.se"})
    assert resp.status_code == 400
    # Both missing
    resp = client.post("/api/login", json={})
    assert resp.status_code == 400
    # Malformed email - counts as non existing
    resp = client.post(
        "/api/login", json={"email": "malformedemail", "password": "password"}
    )
    assert resp.status_code == 401
    # Wrong password
    resp = client.post(
        "/api/login", json={"email": "user@email.se", "password": "password123"}
    )
    assert resp.status_code == 401


def test_upload_document_route(client):
    """Test document upload endpoint."""
    file_path = script_dir / "storage" / "files" / "username" / "input.pdf"
    # open dummy file
    with open(file_path, "rb") as f:
        parameters = {"file": (f, "input.pdf"), "name": "My File"}

        resp = client.post(
            "/api/upload-document", data=parameters, content_type="multipart/form-data"
        )
        resp_data = resp.get_json()

        # tests when fully functional
        # basic tests
        assert resp.status_code == 201
        assert resp.is_json
        # check types
        assert isinstance(
            resp_data.get("id"), int
        )  # was string! Specification is wrong.
        assert isinstance(resp_data.get("name"), str)
        assert isinstance(resp_data.get("creation"), str) and datetime.fromisoformat(
            resp_data.get("creation")
        )
        assert isinstance(resp_data.get("sha256"), str)
        assert isinstance(resp_data.get("size"), int)
        # check value
        assert resp_data.get("name") == parameters["name"]

    # Test with missing file
    resp = client.post("/api/upload-document")
    assert resp.status_code == 400

    # Test with too big file, 51 Mb
    content = b"%PDF-1.4\n" + b"0" * (50 * 1024 * 1024 + 1)  # 50MB + 1 byte
    stream = BytesIO(content)
    file_storage = FileStorage(
        stream=stream, filename="bigfile.pdf", content_type="application/pdf"
    )

    # Need to patch the content length, not included in flask test server
    with patch.object(
        FileStorage, "content_length", new_callable=PropertyMock
    ) as mock_content_length:
        mock_content_length.return_value = len(content)

        data = {
            "file": (
                file_storage.stream,
                file_storage.filename,
                file_storage.content_type,
            ),
            "name": "My Big File",
        }
        resp = client.post(
            "/api/upload-document", data=data, content_type="multipart/form-data"
        )
        assert resp.status_code == 413

    # Test with type error, txt file
    resp = client.post(
        "/api/upload-document",
        data={"file": (BytesIO(b"example"), "test.txt", "text/plain"), "name": "file"},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 415


def test_list_documents_route(client):
    """Test document list endpoint."""
    resp = client.get("/api/list-documents")
    resp_data = resp.get_json()

    # basic tests
    assert resp.status_code == 200
    assert resp.is_json
    # check types
    # extract data
    doc_list = resp_data.get("documents")
    assert isinstance(doc_list, list)
    # cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), int)  # was string! Specification is wrong.
        assert isinstance(elem.get("name"), str)
        assert isinstance(elem.get("creation"), str) and datetime.fromisoformat(
            elem.get("creation")
        )
        assert isinstance(elem.get("sha256"), str)
        assert isinstance(elem.get("size"), int)


def test_list_versions_route(client):
    """Test list versions endpoint."""
    parameters = {"documentid": 1}
    resp = client.get("/api/list-versions", query_string=parameters)
    # resp = client.get("/api/list-versions/1") #for test without parameters
    resp_data = resp.get_json()

    # basic tests
    assert resp.status_code == 200
    assert resp.is_json
    # check types
    # extract data
    doc_list = resp_data.get("versions")
    assert isinstance(doc_list, list)
    # cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), str)
        assert isinstance(elem.get("documentid"), str)
        # check the version is from the correct document
        assert elem.get("documentid") == str(parameters["documentid"])
        assert isinstance(elem.get("link"), str)
        assert isinstance(elem.get("intended_for"), str)
        assert isinstance(elem.get("secret"), str)
        assert isinstance(elem.get("method"), str)

    # Test with no parameters
    resp = client.get("/api/list-versions")
    assert resp.status_code == 400
    # Test with json parameters
    resp = client.get("/api/list-versions", json=parameters)
    assert resp.status_code == 400
    # Test with wrong parameters (missing file)
    resp = client.get("/api/list-versions", query_string={"documentid": 4})
    assert resp.status_code == 404


def test_list_all_versions_route(client):
    """Test list all versions endpoint."""
    # call without parameters
    resp = client.get("/api/list-all-versions")  # Fix list all versions on API.md!
    resp_data = resp.get_json()

    # basic tests
    assert resp.status_code == 200
    assert resp.is_json
    # check types
    # extract data
    doc_list = resp_data.get("versions")
    assert isinstance(doc_list, list)
    # cycle through each element in the list
    for elem in doc_list:
        assert isinstance(elem.get("id"), str)
        assert isinstance(elem.get("documentid"), str)
        assert isinstance(elem.get("link"), str)
        assert isinstance(elem.get("intended_for"), str)
        assert isinstance(elem.get("secret"), str)
        assert isinstance(elem.get("method"), str)


def test_get_document_route(client):
    """Test get document endpoint."""
    parameters = {"documentid": 1}
    resp = client.get("/api/get-document", query_string=parameters)
    # resp = client.get("/api/get-document/1") #for test without parameters

    # Check Content-Type
    is_pdf = resp.headers.get("Content-Type") == "application/pdf"
    # Check Content-Disposition for 'inline'
    content_disposition = resp.headers.get("Content-Disposition", "")
    is_inline = "inline" in content_disposition.lower()
    # Oracle
    assert is_pdf
    assert is_inline

    # Test with no parameters
    resp = client.get("/api/get-document")
    assert resp.status_code == 400
    # Test with json parameters
    resp = client.get("/api/get-document", json=parameters)
    assert resp.status_code == 400
    # Test with wrong parameters (missing file)
    resp = client.get("/api/get-document", query_string={"documentid": 4})
    assert resp.status_code == 404


def test_get_watermarking_methods_route(client):
    """Test get watermarking methods endpoint."""
    resp = client.get("/api/get-watermarking-methods")
    data = resp.get_json()

    # basic tests
    assert resp.status_code == 200
    assert resp.is_json
    # check types
    assert isinstance(data.get("count"), int)
    methods = data.get("methods")
    assert isinstance(methods, list)
    for i in range(0, data.get("count")):
        assert isinstance(methods[i].get("description"), str)
        assert isinstance(methods[i].get("name"), str)


def test_create_watermark_route(client):
    """Test create watermark endpoint."""
    parameters = {
        "method": "robust-xmp",
        "position": "metadata-only",
        "key": "key",
        "secret": "secret",
        "intended_for": "Mickey Mouse",
        "id": 1,
    }
    # parameters_no_id = {
    #    "method": "robust-xmp",
    #    "position": "metadata-only",
    #    "key": "key",
    #    "secret": "secret",
    #    "intended_for": "Mickey Mouse",
    # }
    resp = client.post("/api/create-watermark", json=parameters)
    # resp = client.post("/apicreate-watermark/1", json=parameters_no_id)
    data = resp.get_json()

    # basic tests
    assert resp.status_code == 201
    assert resp.is_json
    # check types
    assert isinstance(data.get("id"), int)
    assert isinstance(data.get("documentid"), int)
    assert isinstance(data.get("link"), str)
    assert isinstance(data.get("intended_for"), str)
    assert isinstance(data.get("method"), str)
    assert isinstance(data.get("position"), str)
    assert isinstance(data.get("filename"), str)
    assert isinstance(data.get("size"), int)
    # check values
    assert data.get("documentid") == parameters["id"]
    assert data.get("intended_for") == parameters["intended_for"]
    assert data.get("method") == parameters["method"]
    assert data.get("position") == parameters["position"]

    # Tests with wrong parameters
    # Test with exact same call:
    # should return database insertion error (Non unique entry)
    resp = client.post("/api/create-watermark", json=parameters)
    assert resp.status_code == 503
    # Non existant method
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "watermarkmethod",
            "position": "metadata-only",
            "key": "key",
            "secret": "secret",
            "intended_for": "Mickey Mouse",
            "id": 1,
        },
    )
    assert resp.status_code == 400
    # Non existant document
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "robust-xmp",
            "position": "metadata-only",
            "key": "key",
            "secret": "secret",
            "intended_for": "Mickey Mouse",
            "id": 8,
        },
    )
    assert resp.status_code == 404
    # Missing id
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "robust-xmp",
            "position": "metadata-only",
            "key": "key",
            "secret": "secret",
            "intended_for": "Mickey Mouse",
        },
    )
    assert resp.status_code == 400
    # Missing method
    resp = client.post(
        "/api/create-watermark",
        json={
            "position": "metadata-only",
            "key": "key",
            "secret": "secret",
            "intended_for": "Mickey Mouse",
            "id": 1,
        },
    )
    assert resp.status_code == 400
    # Missing position: no issue if method ignores
    # (NB: must change intended_for or secret etc! Else integrity error.)
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "overlay-watermark",
            "key": "key",
            "secret": "secret",
            "intended_for": "John",
            "id": 1,
        },
    )
    assert resp.status_code == 201
    # Missing key
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "robust-xmp",
            "position": "metadata-only",
            "secret": "secret",
            "intended_for": "Mickey Mouse",
            "id": 1,
        },
    )
    assert resp.status_code == 400
    # Missing secret
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "robust-xmp",
            "position": "metadata-only",
            "key": "key",
            "intended_for": "Mickey Mouse",
            "id": 1,
        },
    )
    assert resp.status_code == 400
    # Missing recipient
    resp = client.post(
        "/api/create-watermark",
        json={
            "method": "robust-xmp",
            "position": "metadata-only",
            "key": "key",
            "secret": "secret",
            "id": 1,
        },
    )
    assert resp.status_code == 400


def test_read_watermark_route(client):
    """Test read watermark endpoint."""
    file_path = script_dir / "storage" / "files" / "username" / "input.pdf"
    # Upload watermarked file to the app
    with open(file_path, "rb") as f:
        data = {"file": (f, "watermarked.pdf"), "name": "Water File"}
        upload_resp = client.post(
            "/api/upload-document", data=data, content_type="multipart/form-data"
        )
        upload_resp_data = upload_resp.get_json()
        assert upload_resp.status_code == 201
        assert upload_resp_data.get("id") == 2
    # Test the route

    parameters = {
        "method": "overlay-watermark",
        "position": "metadata-only",
        "key": "strong-password",
        "id": 2,
    }
    # parameters_no_id = {
    #    "method": "overlay-watermark",
    #    "position": "metadata-only",
    #    "key": "strong-password",
    # }
    resp = client.post("/api/read-watermark", json=parameters)
    # resp = client.post("/api/read-watermark/2", json=parameters_no_id)
    data = resp.get_json()

    # basic tests
    assert resp.status_code == 201
    assert resp.is_json
    # check types
    assert isinstance(data.get("documentid"), int)
    assert isinstance(data.get("secret"), str)
    assert isinstance(data.get("method"), str)
    assert isinstance(data.get("position"), str)
    # check values
    assert data.get("documentid") == parameters["id"]
    assert data.get("method") == parameters["method"]
    assert data.get("position") == parameters["position"]

    # Tests with wrong parameters
    # Non existant id
    resp = client.post(
        "/api/read-watermark",
        json={
            "method": "overlay-watermark",
            "position": "metadata-only",
            "key": "strong-password",
            "id": 8,
        },
    )
    assert resp.status_code == 404
    # Missing id
    resp = client.post(
        "/api/read-watermark",
        json={
            "method": "overlay-watermark",
            "position": "metadata-only",
            "key": "strong-password",
        },
    )
    assert resp.status_code == 400
    # Missing method
    resp = client.post(
        "/api/read-watermark",
        json={"position": "metadata-only", "key": "strong-password", "id": 2},
    )
    assert resp.status_code == 400
    # Missing position (no problem)
    resp = client.post(
        "/api/read-watermark",
        json={"method": "overlay-watermark", "key": "strong-password", "id": 2},
    )
    assert resp.status_code == 201
    # Missing key
    resp = client.post(
        "/api/read-watermark",
        json={"method": "overlay-watermark", "position": "metadata-only", "id": 2},
    )
    assert resp.status_code == 400


def test_delete_document_route(client):
    document_id = {"id": 2}
    resp = client.delete("/api/delete-document", json=document_id)
    # resp = client.delete("/api/delete-document/2")

    assert resp.status_code == 200
    # Test file is deleted
    resp_deletion = client.get("/api/get-document/2")
    assert resp_deletion.status_code == 404

    # Test missing id
    resp = client.delete("/api/delete-document")
    assert resp.status_code == 400
    # Test missing file
    resp = client.delete("/api/delete-document/2")
    assert resp_deletion.status_code == 404


# Helpers for RMAP routes test
def load_public_key(pubkey_path: str) -> pgpy.PGPKey:
    with open(pubkey_path) as f:
        key_data = f.read()
    key, _ = pgpy.PGPKey.from_blob(key_data)
    return key


def encrypt_payload(data: dict, pubkey: pgpy.PGPKey) -> str:
    json_str = json.dumps(data)
    message = pgpy.PGPMessage.new(json_str)
    encrypted_message = pubkey.encrypt(message)

    return str(encrypted_message)  # Return ASCII-armored PGP string


def encrypt_payload_for_server(data: dict) -> str:
    """
    Encrypts and ASCII-armors the input JSON dictionary, then base64-encodes it.
    This simulates what the client would send in a real RMAP flow.
    """
    # TODO: Implement real PGP encryption using the server’s public key
    public_key_server_path = str(
        Path(__file__).parent.parent / "public-keys" / "pki" / "Group_13.asc"
    )
    public_key = load_public_key(public_key_server_path)
    armored_pgp = encrypt_payload(data, public_key)

    # Now base64-encode the ASCII-armored text
    b64_encoded = base64.b64encode(armored_pgp.encode("utf-8")).decode("utf-8")
    return b64_encoded


def decrypt_server_response(
    payload_b64: str,
    client_privkey_path: str,
    passphrase: str = "",  # nosec test-only
) -> dict:
    # Load key
    client_key, _ = pgpy.PGPKey.from_file(client_privkey_path)

    # Decoding
    armored = base64.b64decode(payload_b64).decode("utf-8")
    pgp_msg = pgpy.PGPMessage.from_blob(armored)
    # Unlock key and decrypt
    if client_key.is_protected:
        with client_key.unlock(passphrase):
            decrypted_msg = client_key.decrypt(pgp_msg)
    else:
        decrypted_msg = client_key.decrypt(pgp_msg)

    return json.loads(decrypted_msg.message)


# Testing RMAP routes
def test_rmap_initiate(client):
    # Prepare payload
    test_nonce = 12345678
    test_identity = "Test_Identity"

    encrypted_payload = encrypt_payload_for_server(
        {"nonceClient": test_nonce, "identity": test_identity}
    )

    # Call route
    response = client.post("/api/rmap-initiate", json={"payload": encrypted_payload})

    assert response.status_code == 200
    json_data = response.get_json()
    assert "payload" in json_data

    # Decrypt and inspect response payload
    decrypted = decrypt_server_response(
        json_data["payload"],
        client_privkey_path=str(Path(__file__).parent / "mock_test_keys" / "pv.asc"),
        passphrase=os.environ.get("TEST_PASSPHRASE", ""),
    )
    assert decrypted["nonceClient"] == test_nonce
    assert isinstance(decrypted["nonceServer"], int)

    # Test with wrong parameters
    # Missing params
    response = client.post("/api/rmap-initiate")
    assert response.status_code == 400

    # Wrong format params
    response = client.post("/api/rmap-initiate", json={"payload": "wrongformatstring"})
    assert response.status_code == 503


def test_rmap_get_link(client, shared_link):
    # Step 0: Create RMAP service user to assign document to
    resp = client.post(
        "/api/create-user",
        json={
            "login": "rmap_service",
            "password": "password_rmap",  # nosec B106
            "email": "service@rmap.su",
        },
    )
    assert resp.status_code == 201
    # Step 1: Initiate RMAP to get nonceServer
    test_nonce = 12345678
    test_identity = "Test_Identity"

    encrypted_payload = encrypt_payload_for_server(
        {"nonceClient": test_nonce, "identity": test_identity}
    )

    response = client.post("/api/rmap-initiate", json={"payload": encrypted_payload})
    assert response.status_code == 200
    json_data = response.get_json()
    assert "payload" in json_data

    # Decrypt response to get the actual nonceServer
    decrypted = decrypt_server_response(
        json_data["payload"],
        client_privkey_path=str(Path(__file__).parent / "mock_test_keys" / "pv.asc"),
        passphrase=os.environ.get("TEST_PASSPHRASE", ""),
    )
    nonce_server = decrypted["nonceServer"]

    # Step 2: Use that nonceServer in the rmap-get-link call
    encrypted_payload = encrypt_payload_for_server({"nonceServer": nonce_server})

    response = client.post("/api/rmap-get-link", json={"payload": encrypted_payload})
    assert response.status_code == 200
    json_data = response.get_json()

    assert "result" in json_data
    assert isinstance(json_data["result"], str)
    assert len(json_data["result"]) == 32
    shared_link["version_link"] = json_data.get("result")

    # Test with wrong parameters
    # Missing params
    response = client.post("/api/rmap-get-link")
    assert response.status_code == 400

    # Wrong format params
    response = client.post("/api/rmap-get-link", json={"payload": "wrongformatstring"})
    assert response.status_code == 503


# Retrieve the watermarked document using the link
def test_get_version_route(client, shared_link):
    route = "/api/get-version/" + shared_link.get("version_link").strip()
    resp = client.get(route)

    # Check Content-Type
    is_pdf = resp.headers.get("Content-Type") == "application/pdf"
    # Check Content-Disposition for 'inline'
    content_disposition = resp.headers.get("Content-Disposition", "")
    is_inline = "inline" in content_disposition.lower()
    # Oracle
    assert is_pdf
    assert is_inline

    # Test with malformed request
    resp = client.get("/api/get-version/123malformedlink")
    assert resp.status_code == 404

    # Test with missing link
    resp = client.get("/api/get-version")
    assert resp.status_code == 404
