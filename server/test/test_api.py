from server import app
from flask import jsonify
from datetime import datetime


def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200  # nosec B101
    assert resp.is_json  # nosec B101

def test_create_user_route():
    client = app.test_client()
    parameters = {"login":"username", "password":"password", "email":"user@email.se"}
    json_parameters = jsonify(parameters)
    resp = client.post("/create-user", json=json_parameters)

    #basic tests
    assert resp.status_code == 201
    assert resp.is_json
    #check types
    assert isinstance(resp.get("id"), int)
    assert isinstance(resp.get("login"), str) 
    assert isinstance(resp.get("email"), str)
    #check values are what we submitted
    assert resp.get("login") == parameters["login"]
    assert resp.get("email") == parameters["email"]

def test_login_route():
    client = app.test_client()
    parameters = {"email":"user@email.se", "password":"password"}
    json_parameters = jsonify(parameters)
    resp = client.post("/login", json=json_parameters)

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types
    assert isinstance(resp.get("token"), str) 
    assert isinstance(resp.get("token_type"), str)
    assert isinstance(resp.get("expires_in"), int)
    #check val
    assert resp.get("token_type") == "bearer"

def test_upload_document_route():
    client = app.test_client()
    pdf_file = "" #TODO add dummy file for testing
    parameters = {"file":pdf_file, "name":"My File"}
    resp = client.post("/login", files=parameters)

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







