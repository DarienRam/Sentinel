import pytest
from sqlalchemy import select

from app.models import Scan, User


@pytest.mark.parametrize("login", ["' OR 1=1 --", "analyst@example.com' OR '1'='1", "'; DROP TABLE users; --"])
def test_sql_injection_login_cannot_authenticate_or_change_rows(api_client, db_session, login):
    response = api_client.post("/auth/login", json={"login": login, "password": "synthetic-password"})
    assert response.status_code == 401
    assert login not in response.text
    assert db_session.scalars(select(User)).all() == []


def test_hostile_scan_and_feedback_are_json_data_not_html(api_client):
    payload = '<script>window.syntheticXssExecuted=true</script><img src=x onerror="alert(1)">'
    scan = api_client.post("/scans", json={"input_type": "message", "raw_content": payload})
    assert scan.status_code == 200
    scan_id = scan.json()["id"]
    result = api_client.post(f"/scans/{scan_id}/feedback", json={"feedback": "Correct", "feedback_note": payload})
    assert result.status_code == 200
    assert result.headers["content-type"] == "application/json"
    assert result.json()["feedback_note"] == payload
    assert api_client.get(f"/scans/{scan_id}").json()["raw_content"] == payload


def test_oversize_feedback_is_rejected_without_echo_or_mutation(api_client):
    scan = api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic feedback budget test."})
    scan_id = scan.json()["id"]
    note = "synthetic-sensitive-note-" * 50
    response = api_client.post(f"/scans/{scan_id}/feedback", json={"feedback": "Correct", "feedback_note": note})
    assert response.status_code == 422 and note not in response.text
    assert api_client.get(f"/scans/{scan_id}").json()["feedback"] is None


def test_database_read_failure_is_controlled_without_sql_or_input_leak(api_client, monkeypatch):
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import OperationalError
    def broken(*args, **kwargs):
        raise OperationalError("private-query", {"raw": "private-value"}, Exception("private connection string"))
    monkeypatch.setattr(Session, "_execute_internal", broken)
    response = api_client.get("/scans")
    assert response.status_code == 503
    assert response.json() == {"detail": "Database service unavailable."}
