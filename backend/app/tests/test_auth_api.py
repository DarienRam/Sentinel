from fastapi.testclient import TestClient


def test_register_creates_user_without_exposing_password(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/auth/register",
        json={
            "username": "Darien",
            "email": "Darien@example.com",
            "password": "strong-password-123",
        },
    )

    assert response.status_code == 201
    user = response.json()
    assert user["id"] == 1
    assert user["username"] == "darien"
    assert user["email"] == "darien@example.com"
    assert "password" not in user
    assert "password_hash" not in user


def test_register_rejects_duplicate_username_or_email(
    api_client: TestClient,
) -> None:
    payload = {
        "username": "analyst",
        "email": "analyst@example.com",
        "password": "strong-password-123",
    }
    first_response = api_client.post("/auth/register", json=payload)
    duplicate_response = api_client.post("/auth/register", json=payload)

    assert first_response.status_code == 201
    assert duplicate_response.status_code == 409
    assert duplicate_response.json()["detail"] == "Username or email is already registered."


def test_login_returns_token_and_auth_me_returns_user(
    api_client: TestClient,
) -> None:
    api_client.post(
        "/auth/register",
        json={
            "username": "analyst",
            "email": "analyst@example.com",
            "password": "strong-password-123",
        },
    )

    login_response = api_client.post(
        "/auth/login",
        json={
            "login": "analyst@example.com",
            "password": "strong-password-123",
        },
    )

    assert login_response.status_code == 200
    token_payload = login_response.json()
    assert token_payload["token_type"] == "bearer"
    assert token_payload["access_token"]
    assert token_payload["user"]["email"] == "analyst@example.com"

    profile_response = api_client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token_payload['access_token']}"},
    )

    assert profile_response.status_code == 200
    profile = profile_response.json()
    assert profile["username"] == "analyst"
    assert profile["email"] == "analyst@example.com"


def test_login_rejects_bad_password(api_client: TestClient) -> None:
    api_client.post(
        "/auth/register",
        json={
            "username": "analyst",
            "email": "analyst@example.com",
            "password": "strong-password-123",
        },
    )

    response = api_client.post(
        "/auth/login",
        json={
            "login": "analyst",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid login credentials."


def test_auth_me_rejects_invalid_token(api_client: TestClient) -> None:
    response = api_client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not-a-real-token"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired authentication token."
