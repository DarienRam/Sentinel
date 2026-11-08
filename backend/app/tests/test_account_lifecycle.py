import time

import jwt
import pytest

from app.core.account_sessions import account_cookie_name
from app.core.config import settings

PASSWORD = "synthetic-password-123"


def register(client, name="analyst"):
    response = client.post("/auth/register", json={"username": name, "email": name + "@example.com", "password": PASSWORD})
    assert response.status_code == 201


def login(client, *, cookie=False):
    response = client.post("/auth/login" + ("?transport=cookie" if cookie else ""),
                           json={"login": "analyst", "password": PASSWORD})
    assert response.status_code == 200
    return response


def test_cookie_account_restore_logout_and_replay(api_client):
    register(api_client)
    response = login(api_client, cookie=True)
    assert "access_token" not in response.json()
    header = response.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=strict" in header and "domain=" not in header
    token = api_client.cookies.get(account_cookie_name())
    session = api_client.get("/auth/session")
    assert session.status_code == 200 and session.headers["cache-control"] == "no-store"
    api_client.headers["X-CSRF-Token"] = session.json()["csrf_token"]
    assert api_client.post("/auth/logout").status_code == 204
    assert api_client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert api_client.get("/auth/me").status_code == 401


def test_bearer_logout_revokes_only_that_session(api_client):
    register(api_client)
    first = login(api_client).json()["access_token"]
    second = login(api_client).json()["access_token"]
    headers = {"Authorization": "Bearer " + first}
    assert api_client.post("/auth/logout", headers=headers).status_code == 204
    assert api_client.get("/auth/me", headers=headers).status_code == 401
    assert api_client.get("/auth/me", headers={"Authorization": "Bearer " + second}).status_code == 200


def test_password_change_preserves_account_data_and_invalidates_all_sessions(api_client):
    register(api_client)
    first = login(api_client).json()["access_token"]
    second = login(api_client).json()["access_token"]
    headers = {"Authorization": "Bearer " + first}
    created = api_client.post("/scans", headers=headers,
                               json={"input_type": "message", "raw_content": "Synthetic account history.", "save_scan": True})
    assert created.status_code == 200
    assert api_client.post("/auth/password", headers=headers,
                           json={"current_password": "incorrect-password", "new_password": "new-synthetic-password"}).status_code == 401
    assert api_client.post("/auth/password", headers=headers,
                           json={"current_password": PASSWORD, "new_password": "new-synthetic-password"}).status_code == 204
    for token in (first, second):
        assert api_client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert api_client.post("/auth/login", json={"login": "analyst", "password": PASSWORD}).status_code == 401
    new = api_client.post("/auth/login", json={"login": "analyst", "password": "new-synthetic-password"})
    assert new.status_code == 200
    assert api_client.get(f"/scans/{created.json()['id']}", headers={"Authorization": "Bearer " + new.json()["access_token"]}).status_code == 200


@pytest.mark.parametrize("changes", [
    {"exp": 1}, {"iat": int(time.time()) + 86400}, {"nbf": int(time.time()) + 86400},
    {"iss": "other-app"}, {"aud": "other-api"}, {"sub": "999999999999999999999999"},
    {"sub": "-1"}, {"sub": "1 OR 1=1"}, {"exp": "invalid"}, {"jti": "chosen"},
    {"exp": None}, {"iat": True}, {"exp": int(time.time()) + 864000},
])
def test_forged_or_invalid_claims_are_rejected(api_client, changes):
    register(api_client)
    token = login(api_client).json()["access_token"]
    payload = jwt.decode(token, settings.secret_key.get_secret_value(), algorithms=["HS256"], audience="sentinel-api")
    payload.update(changes)
    forged = jwt.encode(payload, settings.secret_key.get_secret_value(), algorithm="HS256")
    assert api_client.get("/auth/me", headers={"Authorization": "Bearer " + forged}).status_code == 401


def test_legacy_missing_claims_and_wrong_signature_are_rejected(api_client):
    for token in (jwt.encode({"sub": "1", "exp": int(time.time()) + 300}, settings.secret_key.get_secret_value(), algorithm="HS256"),
                  jwt.encode({"sub": "1", "exp": int(time.time()) + 300}, "other-synthetic-signing-key-long-enough", algorithm="HS256")):
        assert api_client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_cookie_mutations_and_bootstrap_require_csrf_origin(api_client):
    register(api_client)
    login(api_client, cookie=True)
    assert api_client.post("/auth/logout").status_code == 403  # anonymous CSRF cannot authorize account
    csrf = api_client.get("/auth/session").json()["csrf_token"]
    api_client.headers["X-CSRF-Token"] = csrf
    assert api_client.post("/auth/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    assert api_client.get("/auth/session", headers={"Origin": "https://evil.example"}).status_code == 403
    api_client.headers.pop("Origin")
    assert api_client.post("/auth/login?transport=cookie", json={"login": "analyst", "password": PASSWORD}).status_code == 403
    assert api_client.post("/auth/logout").status_code == 403


def test_expired_server_session_and_bad_authorization_never_fall_back(api_client):
    from app.main import app
    register(api_client)
    login(api_client, cookie=True)
    assert api_client.get("/scans", headers={"Authorization": "Basic chosen"}).status_code == 401
    app.state.security_store.clock = lambda: time.time() + 86400
    assert api_client.get("/scans").status_code == 401
    # Invalid account cookie is cleared, rather than trapping the browser in 401s.
    assert not api_client.cookies.get(account_cookie_name())


def test_production_account_cookie_and_private_response_headers(api_client, monkeypatch):
    register(api_client)
    from app.core.config import settings
    monkeypatch.setattr(settings, "app_env", "production")
    response = login(api_client, cookie=True)
    header = response.headers["set-cookie"].lower()
    assert header.startswith("__host-sentinel_account=") and "; secure" in header
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_wrong_password_does_not_clear_valid_account_cookie(api_client):
    register(api_client)
    session = login(api_client, cookie=True).json()
    api_client.headers["X-CSRF-Token"] = session["csrf_token"]
    token = api_client.cookies.get(account_cookie_name())
    response = api_client.post("/auth/password", json={"current_password": "wrong-password", "new_password": "new-synthetic-password"})
    assert response.status_code == 401
    assert api_client.cookies.get(account_cookie_name()) == token
    assert api_client.get("/auth/me").status_code == 200
