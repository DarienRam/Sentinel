from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.models.scan import Scan as ScanModel


def _register_and_login(
    api_client: TestClient,
    username: str,
    email: str,
) -> dict[str, str]:
    password = "strong-password-123"
    api_client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    login_response = api_client.post(
        "/auth/login",
        json={
            "login": email,
            "password": password,
        },
    )
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_scan_api_create_list_and_detail_flow(api_client: TestClient) -> None:
    create_response = api_client.post(
        "/scans",
        json={
            "input_type": "url",
            "raw_content": "http://verify-bank-login.ru/account-suspended",
            "save_scan": False,
            "retention_days": 7,
        },
    )

    assert create_response.status_code == 200
    created_scan = create_response.json()
    assert created_scan["id"] == 1
    assert created_scan["risk_level"] in {"Medium", "High"}
    assert created_scan["confidence_score"] >= 0
    assert created_scan["finding_details"]
    assert created_scan["detected_categories"]
    assert created_scan["is_saved"] is False
    assert created_scan["expires_at"] is not None

    list_response = api_client.get("/scans")

    assert list_response.status_code == 200
    scan_history = list_response.json()
    assert len(scan_history) == 1
    assert scan_history[0]["id"] == created_scan["id"]

    detail_response = api_client.get(f"/scans/{created_scan['id']}")

    assert detail_response.status_code == 200
    scan_detail = detail_response.json()
    assert scan_detail["id"] == created_scan["id"]
    assert scan_detail["raw_content"] == created_scan["raw_content"]


def test_anonymous_scan_history_is_scoped_to_browser_session(
    api_client: TestClient,
) -> None:
    create_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Are you available? Send me the OTP code immediately.",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    assert create_response.status_code == 200
    scan_id = create_response.json()["id"]

    api_client.cookies.clear()
    session = api_client.post("/auth/anonymous-session")
    api_client.headers.update({"X-CSRF-Token": session.json()["csrf_token"]})
    assert api_client.get("/scans").json() == []
    assert api_client.get(f"/scans/{scan_id}").status_code == 404


def test_anonymous_scan_cannot_be_saved_permanently(api_client: TestClient) -> None:
    response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Are you available? Send me the OTP code immediately.",
            "save_scan": True,
            "retention_days": 7,
        },
    )

    assert response.status_code == 403
    assert "Log in" in response.json()["detail"]


def test_authenticated_user_can_manage_scan_storage_and_delete(
    api_client: TestClient,
) -> None:
    headers = _register_and_login(api_client, "storage-user", "storage@example.com")
    create_response = api_client.post(
        "/scans",
        headers=headers,
        json={
            "input_type": "message",
            "raw_content": "Are you available? Send me the OTP code immediately.",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    scan_id = create_response.json()["id"]

    permanent_response = api_client.patch(
        f"/scans/{scan_id}/storage",
        headers=headers,
        json={"save_scan": True},
    )
    assert permanent_response.status_code == 200
    assert permanent_response.json()["is_saved"] is True
    assert permanent_response.json()["expires_at"] is None

    temporary_response = api_client.patch(
        f"/scans/{scan_id}/storage",
        headers=headers,
        json={"save_scan": False, "retention_days": 14},
    )
    assert temporary_response.status_code == 200
    assert temporary_response.json()["is_saved"] is False
    assert temporary_response.json()["expires_at"] is not None

    delete_response = api_client.delete(f"/scans/{scan_id}", headers=headers)
    assert delete_response.status_code == 204
    assert api_client.get(f"/scans/{scan_id}", headers=headers).status_code == 404


def test_scan_api_limit_returns_latest_scans_in_descending_order(
    api_client: TestClient,
) -> None:
    created_ids: list[int] = []

    for index in range(3):
        response = api_client.post(
            "/scans",
            json={
                "input_type": "message",
                "raw_content": f"Urgent payroll issue {index}: send the OTP code now.",
                "save_scan": False,
                "retention_days": 7,
            },
        )

        assert response.status_code == 200
        created_ids.append(response.json()["id"])

    list_response = api_client.get("/scans", params={"limit": 2})

    assert list_response.status_code == 200
    scan_history = list_response.json()
    assert [scan["id"] for scan in scan_history] == created_ids[::-1][:2]

    summary_response = api_client.get("/scans/analytics/summary", params={"limit": 2})

    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["total_scans"] == 2


def test_scan_api_rejects_invalid_limit(api_client: TestClient) -> None:
    response = api_client.get("/scans", params={"limit": 0})

    assert response.status_code == 422


def test_scan_api_days_filter_limits_history_and_summary(api_client: TestClient) -> None:
    first_response = api_client.post(
        "/scans",
        json={
            "input_type": "url",
            "raw_content": "http://verify-bank-login.ru/account-suspended",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    second_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Are you available? Send me the OTP code immediately.",
            "save_scan": False,
            "retention_days": 7,
        },
    )

    with SessionLocal() as db:
        older_scan = db.get(ScanModel, first_response.json()["id"])
        recent_scan = db.get(ScanModel, second_response.json()["id"])
        assert older_scan is not None
        assert recent_scan is not None
        older_scan.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        recent_scan.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()

    filtered_history_response = api_client.get("/scans", params={"days": 7})
    filtered_summary_response = api_client.get(
        "/scans/analytics/summary",
        params={"days": 7},
    )

    assert filtered_history_response.status_code == 200
    filtered_history = filtered_history_response.json()
    assert len(filtered_history) == 1
    assert filtered_history[0]["id"] == second_response.json()["id"]

    assert filtered_summary_response.status_code == 200
    filtered_summary = filtered_summary_response.json()
    assert filtered_summary["total_scans"] == 1


def test_scan_api_rejects_invalid_days_filter(api_client: TestClient) -> None:
    response = api_client.get("/scans", params={"days": 0})

    assert response.status_code == 422


def test_scan_api_feedback_and_analytics_flow(api_client: TestClient) -> None:
    first_response = api_client.post(
        "/scans",
        json={
            "input_type": "email",
            "raw_content": "Dear customer, verify your password within 24 hours.",
            "save_scan": False,
            "retention_days": 14,
        },
    )
    api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Friendly reminder about our team lunch tomorrow.",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    scan_id = first_response.json()["id"]

    feedback_response = api_client.post(
        f"/scans/{scan_id}/feedback",
        json={
            "feedback": "Correct",
            "feedback_note": "API test note.",
        },
    )

    assert feedback_response.status_code == 200
    updated_scan = feedback_response.json()
    assert updated_scan["feedback"] == "Correct"
    assert updated_scan["feedback_note"] == "API test note."
    assert updated_scan["is_saved"] is False
    assert updated_scan["expires_at"] is not None

    summary_response = api_client.get("/scans/analytics/summary")

    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["total_scans"] == 2
    assert summary["feedback_count"] == 1
    assert summary["needs_review_count"] == 1
    assert summary["high_risk_needing_feedback_count"] >= 0
    assert summary["average_risk_score"] >= 0
    assert summary["average_confidence_score"] >= 0
    assert len(summary["input_type_counts"]) == 3
    assert len(summary["feedback_breakdown"]) == 3
    assert summary["common_categories"]
    assert summary["comparison"] is None


def test_scan_api_summary_includes_latest_high_risk_and_input_breakdown(
    api_client: TestClient,
) -> None:
    low_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Friendly reminder about our team lunch tomorrow.",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    high_response = api_client.post(
        "/scans",
        json={
            "input_type": "email",
            "raw_content": (
                "Hi, this is the CEO. Keep this between us and update the bank account "
                "for the attached invoice with the new banking details today."
            ),
            "save_scan": False,
            "retention_days": 7,
        },
    )

    with SessionLocal() as db:
        low_scan = db.get(ScanModel, low_response.json()["id"])
        high_scan = db.get(ScanModel, high_response.json()["id"])
        assert low_scan is not None
        assert high_scan is not None
        low_scan.created_at = datetime.now(timezone.utc) - timedelta(days=2)
        high_scan.created_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()

    summary_response = api_client.get("/scans/analytics/summary")

    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["latest_high_risk_created_at"] is not None
    assert any(
        item["input_type"] == "email" and item["count"] == 1
        for item in summary["input_type_counts"]
    )
    assert any(
        item["input_type"] == "message" and item["count"] == 1
        for item in summary["input_type_counts"]
    )


def test_scan_api_summary_comparison_tracks_previous_window_and_review_backlog(
    api_client: TestClient,
) -> None:
    older_high_response = api_client.post(
        "/scans",
        json={
            "input_type": "email",
            "raw_content": (
                "Urgent payroll issue. Keep this between us and send the gift card codes "
                "for the bank payment today."
            ),
            "save_scan": False,
            "retention_days": 7,
        },
    )
    current_low_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Friendly reminder about our team lunch tomorrow.",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    current_high_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": (
                "Are you free? Reply with the security code for the account now. "
                "I cannot speak because I am traveling. Keep this between us."
            ),
            "save_scan": False,
            "retention_days": 7,
        },
    )

    with SessionLocal() as db:
        older_high_scan = db.get(ScanModel, older_high_response.json()["id"])
        current_low_scan = db.get(ScanModel, current_low_response.json()["id"])
        current_high_scan = db.get(ScanModel, current_high_response.json()["id"])
        assert older_high_scan is not None
        assert current_low_scan is not None
        assert current_high_scan is not None
        older_high_scan.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        current_low_scan.created_at = datetime.now(timezone.utc) - timedelta(days=2)
        current_high_scan.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()

    feedback_response = api_client.post(
        f"/scans/{current_low_response.json()['id']}/feedback",
        json={
            "feedback": "Correct",
            "feedback_note": "Reviewed benign reminder.",
        },
    )
    assert feedback_response.status_code == 200

    summary_response = api_client.get(
        "/scans/analytics/summary",
        params={"days": 7},
    )

    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["total_scans"] == 2
    assert summary["feedback_count"] == 1
    assert summary["needs_review_count"] == 1
    assert summary["high_risk_count"] == 1
    assert summary["high_risk_needing_feedback_count"] == 1
    assert summary["comparison"] is not None
    assert summary["comparison"]["previous_total_scans"] == 1
    assert summary["comparison"]["previous_high_risk_count"] == 1
    assert summary["comparison"]["scan_volume_change"] == 1


def test_scan_api_filters_history_and_summary_by_risk_and_feedback_status(
    api_client: TestClient,
) -> None:
    reviewed_high_response = api_client.post(
        "/scans",
        json={
            "input_type": "email",
            "raw_content": (
                "Urgent payroll issue. Keep this between us and send the gift card codes "
                "for the bank payment today."
            ),
            "save_scan": False,
            "retention_days": 7,
        },
    )
    pending_high_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": (
                "Are you free? Reply with the security code for the account now. "
                "I cannot speak because I am traveling. Keep this between us."
            ),
            "save_scan": False,
            "retention_days": 7,
        },
    )
    api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "Friendly reminder about our team lunch tomorrow.",
            "save_scan": False,
            "retention_days": 7,
        },
    )

    feedback_response = api_client.post(
        f"/scans/{reviewed_high_response.json()['id']}/feedback",
        json={
            "feedback": "Correct",
            "feedback_note": "Reviewed high-risk result.",
        },
    )
    assert feedback_response.status_code == 200

    filtered_history_response = api_client.get(
        "/scans",
        params={"risk_level": "High", "feedback_status": "pending"},
    )
    filtered_summary_response = api_client.get(
        "/scans/analytics/summary",
        params={"risk_level": "High", "feedback_status": "pending"},
    )

    assert filtered_history_response.status_code == 200
    filtered_history = filtered_history_response.json()
    assert len(filtered_history) == 1
    assert filtered_history[0]["id"] == pending_high_response.json()["id"]

    assert filtered_summary_response.status_code == 200
    filtered_summary = filtered_summary_response.json()
    assert filtered_summary["total_scans"] == 1
    assert filtered_summary["high_risk_count"] == 1
    assert filtered_summary["feedback_count"] == 0
    assert filtered_summary["needs_review_count"] == 1


def test_scan_api_returns_404_for_missing_scan(api_client: TestClient) -> None:
    response = api_client.get("/scans/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found."


def test_authenticated_scan_history_is_scoped_by_user(
    api_client: TestClient,
) -> None:
    first_user_headers = _register_and_login(
        api_client,
        username="firstanalyst",
        email="first@example.com",
    )
    second_user_headers = _register_and_login(
        api_client,
        username="secondanalyst",
        email="second@example.com",
    )

    first_scan_response = api_client.post(
        "/scans",
        headers=first_user_headers,
        json={
            "input_type": "url",
            "raw_content": "http://first-bank-login.ru/verify-password",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    second_scan_response = api_client.post(
        "/scans",
        headers=second_user_headers,
        json={
            "input_type": "message",
            "raw_content": "Are you available? Send me the OTP code immediately.",
            "save_scan": False,
            "retention_days": 7,
        },
    )

    assert first_scan_response.status_code == 200
    assert second_scan_response.status_code == 200

    first_history_response = api_client.get("/scans", headers=first_user_headers)
    second_history_response = api_client.get("/scans", headers=second_user_headers)
    anonymous_history_response = api_client.get("/scans")
    limited_first_history_response = api_client.get(
        "/scans",
        headers=first_user_headers,
        params={"limit": 1},
    )

    first_history = first_history_response.json()
    second_history = second_history_response.json()
    limited_first_history = limited_first_history_response.json()

    assert first_history_response.status_code == 200
    assert second_history_response.status_code == 200
    assert anonymous_history_response.status_code == 200
    assert limited_first_history_response.status_code == 200
    assert len(first_history) == 1
    assert len(second_history) == 1
    assert len(limited_first_history) == 1
    assert anonymous_history_response.json() == []
    assert first_history[0]["id"] == first_scan_response.json()["id"]
    assert second_history[0]["id"] == second_scan_response.json()["id"]
    assert limited_first_history[0]["id"] == first_scan_response.json()["id"]


def test_authenticated_user_cannot_access_another_users_scan(
    api_client: TestClient,
) -> None:
    first_user_headers = _register_and_login(
        api_client,
        username="firstanalyst",
        email="first@example.com",
    )
    second_user_headers = _register_and_login(
        api_client,
        username="secondanalyst",
        email="second@example.com",
    )

    first_scan_response = api_client.post(
        "/scans",
        headers=first_user_headers,
        json={
            "input_type": "url",
            "raw_content": "http://first-bank-login.ru/verify-password",
            "save_scan": False,
            "retention_days": 7,
        },
    )
    first_scan_id = first_scan_response.json()["id"]

    detail_response = api_client.get(
        f"/scans/{first_scan_id}",
        headers=second_user_headers,
    )
    feedback_response = api_client.post(
        f"/scans/{first_scan_id}/feedback",
        headers=second_user_headers,
        json={
            "feedback": "Correct",
            "feedback_note": "Trying to update another user's scan.",
        },
    )

    assert detail_response.status_code == 404
    assert feedback_response.status_code == 404


def test_unsaved_scan_expires_after_retention_window(api_client: TestClient) -> None:
    create_response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "A suspicious account notice needs review before access remains active.",
            "save_scan": False,
            "retention_days": 30,
        },
    )

    scan_id = create_response.json()["id"]

    with SessionLocal() as db:
        scan = db.get(ScanModel, scan_id)
        assert scan is not None
        scan.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        db.commit()

    history_response = api_client.get("/scans")
    detail_response = api_client.get(f"/scans/{scan_id}")

    assert history_response.status_code == 200
    assert history_response.json() == []
    assert detail_response.status_code == 404


def test_scan_api_rejects_invalid_temporary_retention_window(
    api_client: TestClient,
) -> None:
    response = api_client.post(
        "/scans",
        json={
            "input_type": "message",
            "raw_content": "A suspicious account notice needs review before access remains active.",
            "save_scan": False,
            "retention_days": 21,
        },
    )

    assert response.status_code == 422
    assert "7, 14, or 30" in response.json()["detail"]
