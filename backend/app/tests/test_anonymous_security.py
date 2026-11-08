import time

import pytest

from app.core.anonymous_sessions import cookie_name
from app.core.security_store import credential_key
from app.models.scan import Scan


def create_scan(client):
    response = client.post("/scans", json={"input_type": "message", "raw_content": "A synthetic scan for testing."})
    assert response.status_code == 200
    return response.json()["id"]


def establish(client):
    client.cookies.clear()
    response = client.post("/auth/anonymous-session")
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client.cookies.get(cookie_name()), response.json()


def assert_denied_access(client, scan_id, headers=None):
    assert client.get(f"/scans/{scan_id}", headers=headers).status_code == 404
    assert client.post(f"/scans/{scan_id}/feedback", headers=headers,
                       json={"feedback": "Correct"}).status_code == 404
    assert client.patch(f"/scans/{scan_id}/storage", headers=headers,
                        json={"save_scan": False, "retention_days": 14}).status_code == 404
    assert client.delete(f"/scans/{scan_id}", headers=headers).status_code == 404
    assert client.get("/scans", headers=headers).json() == []
    assert client.get("/scans/analytics/summary", headers=headers).json()["total_scans"] == 0


def login(client, name):
    payload = {"username": name, "email": name + "@example.com", "password": "synthetic-password-123"}
    assert client.post("/auth/register", json=payload).status_code == 201
    response = client.post("/auth/login", json={"login": name, "password": payload["password"]})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_server_cookie_and_refresh_restore_without_exposing_capability(api_client):
    token = api_client.cookies.get(cookie_name())
    assert token and len(token) == 43
    result = api_client.post("/auth/anonymous-session")
    assert token not in result.text
    assert result.headers["cache-control"] == "no-store"
    assert api_client.cookies.get(cookie_name()) == token
    scan_id = create_scan(api_client)
    assert api_client.get(f"/scans/{scan_id}").status_code == 200
    # Re-establishing a valid cookie only restores its CSRF state, not a new owner.
    csrf = api_client.post("/auth/anonymous-session").json()["csrf_token"]
    assert csrf == api_client.headers["X-CSRF-Token"]


def test_cookie_flags(api_client):
    api_client.cookies.clear()
    response = api_client.post("/auth/anonymous-session")
    header = response.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=strict" in header and "path=/" in header
    assert "domain=" not in header


def test_production_cookie_is_host_prefixed_secure_and_http_only(api_client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "app_env", "production")
    response = api_client.post("/auth/anonymous-session")
    header = response.headers["set-cookie"].lower()
    assert header.startswith("__host-sentinel_anon=")
    assert "; secure" in header and "httponly" in header and "domain=" not in header


def test_separate_sessions_cannot_access_or_mutate_each_others_scans(api_client):
    scan_id = create_scan(api_client)
    old = api_client.cookies.get(cookie_name())
    new, _ = establish(api_client)
    assert new != old
    assert_denied_access(api_client, scan_id)


@pytest.mark.parametrize("cookie", ["chosen-id", "!" * 43, "a" * 43, "x" * 500])
def test_forged_malformed_cookie_is_not_identity(api_client, cookie):
    scan_id = create_scan(api_client)
    api_client.cookies.clear()
    api_client.cookies.set(cookie_name(), cookie)
    assert api_client.get(f"/scans/{scan_id}").status_code == 401
    assert api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic content."}).status_code == 401


def test_legacy_header_cannot_claim_existing_history(api_client, db_session):
    # Unique synthetic legacy row. No production records are inspected/migrated.
    row = Scan(anonymous_session_id="known-legacy-id", input_type="message", raw_content="Synthetic legacy text.",
               risk_score=0, confidence_score=80, risk_level="Low", summary="Synthetic", recommendation="Review",
               is_saved=False)
    db_session.add(row)
    db_session.commit()
    assert api_client.get("/scans", headers={"X-Anonymous-Session": "known-legacy-id"}).status_code == 401
    assert api_client.get(f"/scans/{row.id}").status_code == 404
    db_session.refresh(row)
    assert row.raw_content == "Synthetic legacy text."


def test_anonymous_cannot_access_account_scans_and_users_cannot_cross_owners(api_client):
    first = login(api_client, "first")
    response = api_client.post("/scans", headers=first,
                               json={"input_type": "message", "raw_content": "Synthetic account scan."})
    scan_id = response.json()["id"]
    assert_denied_access(api_client, scan_id)
    second = login(api_client, "second")
    assert_denied_access(api_client, scan_id, second)
    assert api_client.get(f"/scans/{scan_id}", headers=first).status_code == 200


def test_authenticated_identity_does_not_adopt_guest_history(api_client):
    scan_id = create_scan(api_client)
    account = login(api_client, "account")
    assert_denied_access(api_client, scan_id, account)
    assert api_client.get(f"/scans/{scan_id}").status_code == 200


@pytest.mark.parametrize("origin,csrf", [("https://evil.example", None), (None, None),
                                       ("http://localhost:3000", "forged")])
def test_cookie_mutations_require_origin_and_csrf(api_client, origin, csrf):
    scan_id = create_scan(api_client)
    api_client.headers.pop("Origin", None)
    api_client.headers.pop("X-CSRF-Token", None)
    headers = {}
    if origin:
        headers["Origin"] = origin
    if csrf:
        headers["X-CSRF-Token"] = csrf
    assert api_client.delete(f"/scans/{scan_id}", headers=headers).status_code == 403
    assert api_client.get(f"/scans/{scan_id}").status_code == 200


def test_bootstrap_rejects_untrusted_or_missing_origin(api_client):
    api_client.cookies.clear()
    api_client.headers.pop("Origin", None)
    assert api_client.post("/auth/anonymous-session").status_code == 403
    assert api_client.post("/auth/anonymous-session", headers={"Origin": "https://evil.example"}).status_code == 403


def test_non_ascii_csrf_is_rejected_without_server_error(api_client):
    response = api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic content."},
                               headers={b"X-CSRF-Token": b"\xff"})
    assert response.status_code == 403


def test_rotation_revokes_old_credential_and_preserves_owner_and_expiration(api_client):
    scan_id = create_scan(api_client)
    old = api_client.cookies.get(cookie_name())
    before = api_client.post("/auth/anonymous-session").json()
    response = api_client.post("/auth/anonymous-session/rotate")
    assert response.status_code == 200
    new = api_client.cookies.get(cookie_name())
    assert new != old and response.json()["expires_at"] == before["expires_at"]
    api_client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    assert api_client.get(f"/scans/{scan_id}").status_code == 200
    api_client.cookies.clear()
    api_client.cookies.set(cookie_name(), old)
    assert api_client.get(f"/scans/{scan_id}").status_code == 401


def test_revocation_and_expiration_deny_replay(api_client):
    from app.main import app

    old = api_client.cookies.get(cookie_name())
    assert api_client.delete("/auth/anonymous-session").status_code == 204
    api_client.cookies.set(cookie_name(), old)
    assert api_client.get("/scans").status_code == 401
    fresh, _ = establish(api_client)
    store = app.state.security_store
    store.clock = lambda: time.time() + 604801
    assert store.load_session(credential_key(fresh)) is None
    assert api_client.get("/scans").status_code == 401


def test_invalid_bearer_cannot_fall_back_to_valid_cookie(api_client):
    scan_id = create_scan(api_client)
    assert api_client.get(f"/scans/{scan_id}", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_expired_target_remains_inaccessible_with_large_purge_backlog(api_client, db_session):
    from datetime import datetime, timedelta, timezone

    ids = [create_scan(api_client)]
    target = db_session.get(Scan, ids[0])
    owner = target.anonymous_session_id
    for _ in range(110):
        db_session.add(Scan(anonymous_session_id=owner, input_type="message", raw_content="Synthetic expired.",
                            risk_score=0, confidence_score=80, risk_level="Low", summary="Test", recommendation="Review",
                            expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
    db_session.commit()
    assert len(api_client.get("/scans").json()) == 1
    assert api_client.get("/scans/analytics/summary").json()["total_scans"] == 1
