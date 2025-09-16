from server import app


def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200  # nosec B101
    assert resp.is_json  # nosec B101

def test_create_user_route():
    client = app.test_client()
    json_parameters = {"login":"username", "password":"password", "email":"user@email.se"}
    resp = client.post("/create-user", json=json_parameters)

    #basic tests
    assert resp.status_code == 201
    assert resp.is_json
    #check types, check non empty
    assert isinstance(resp.get("id"), int)
    assert isinstance(resp.get("login"), str) 
    assert isinstance(resp.get("email"), str)
    #check values are what we submitted
    assert resp.get("login") == json_parameters["login"]
    assert resp.get("email") == json_parameters["email"]

def test_login_route():
    client = app.test_client()
    json_parameters = {"email":"user@email.se", "password":"password"}
    resp = client.post("/login", json=json_parameters)

    #basic tests
    assert resp.status_code == 200
    assert resp.is_json
    #check types, check non empty
    assert isinstance(resp.get("token"), str) 
    assert isinstance(resp.get("token_type"), str)
    assert isinstance(resp.get("expires_in"), int)
    #check val
    assert resp.get("token_type") == "bearer"








