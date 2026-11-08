import bcrypt
import pytest

from app.core.security import hash_password, verify_password
from app.models.user import User


def test_native_bcrypt_rejects_73_bytes():
    with pytest.raises(ValueError):
        bcrypt.hashpw(b"a" * 73, bcrypt.gensalt(rounds=4))


@pytest.mark.parametrize("password", ["a" * 72, "é" * 36, "🔐" * 18])
def test_password_boundary_registration_and_login(api_client, password):
    response = api_client.post("/auth/register", json={
        "username": "boundary", "email": "boundary@example.com", "password": password,
    })
    assert response.status_code == 201
    assert api_client.post("/auth/login", json={"login": "boundary", "password": password}).status_code == 200


@pytest.mark.parametrize("password", ["a" * 73, "a" * 128, "é" * 37, "🔐" * 19, "a" * 71 + "é"])
def test_oversize_password_requests_are_controlled_and_not_truncated(api_client, password):
    prefix = "a" * 72
    api_client.post("/auth/register", json={
        "username": "boundary", "email": "boundary@example.com", "password": prefix,
    })
    assert api_client.post("/auth/register", json={
        "username": "other", "email": "other@example.com", "password": password,
    }).status_code == 422
    assert api_client.post("/auth/login", json={"login": "boundary", "password": password}).status_code == 422
    stored = hash_password(prefix)
    assert not verify_password(password, stored)
    with pytest.raises(ValueError, match="72 UTF-8 bytes"):
        hash_password(password)


@pytest.mark.parametrize("prefix", [b"2a", b"2b", b"2y"])
def test_existing_raw_bcrypt_hashes_login_without_rewrite(api_client, db_session, prefix):
    password = "legacy-café-password"
    original = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))
    stored = (b"$" + prefix + original[3:]).decode()
    user = User(username="legacy", email="legacy@example.com", password_hash=stored)
    db_session.add(user)
    db_session.commit()
    assert api_client.post("/auth/login", json={"login": "legacy", "password": password}).status_code == 200
    assert api_client.post("/auth/login", json={"login": "legacy", "password": password + "x"}).status_code == 401
    db_session.refresh(user)
    assert user.password_hash == stored


def test_invalid_stored_hash_fails_verification():
    assert not verify_password("synthetic-password", "not-a-bcrypt-hash")


def test_invalid_unicode_password_returns_controlled_error(api_client):
    response = api_client.post(
        "/auth/login", content=b'{"login":"analyst","password":"valid-prefix-\\ud800"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert all(set(error) <= {"type", "loc", "msg"} for error in response.json()["detail"])


def test_password_validation_error_does_not_echo_submitted_password(api_client):
    password = "synthetic-private-password-" * 4
    response = api_client.post("/auth/login", json={"login": "analyst", "password": password})
    assert response.status_code == 422
    assert password not in response.text
