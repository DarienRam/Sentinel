import pytest

from app.schemas.scan import ScanCreate
from app.services.scan_engine import analyze_scan


@pytest.mark.parametrize("url", [
    "https://[bad/login", "https://bad]/login", "https://[::1", "https://[not-ipv6]/",
    "https://[127.0.0.1]/", "https://[v1.invalid]/",
    "https://[::1]garbage/", "https://[::1]:80suffix/",
    "https:///missing-host", "https://", "https://.example.com/", "https://example..com/",
    "https://-bad.example/", "https://bad-.example/", "https://bad_host.example/",
    "https://999.1.1.1/", "https://example.com:abc/", "https://example.com:65536/",
    "https://example.com:/", "ftp://example.com/file", "javascript:alert(1)", "file:///etc/passwd",
    "https://example.com/%", "https://example.com/%GG", "https://example.com/%C3%28",
    "https://example.com/%00", "https://example.com/%0d%0aInjected",
    "https://%65xample.com/", "https://example.com\\@evil.example/",
    "https://exa mple.com/", "https://example.com/\npath", "\nhttps://example.com/",
    "https://example.com／evil/", "https://" + "a" * 64 + ".com/", "https://xn--.com/",
    "https://example.com/" + "a" * 5000,
], ids=lambda value: value[:50])
def test_invalid_url_returns_422_without_persisting_scan(api_client, url):
    response = api_client.post("/scans", json={"input_type": "url", "raw_content": url})
    assert response.status_code == 422
    assert api_client.get("/scans").json() == []


@pytest.mark.parametrize("url", [
    "https://example.com/login", "http://verify-bank-login.ru/account-suspended",
    "example.com/login", "localhost:8080/path", "//example.com/path",
    "https://example.com?next=https://other.example/", "example.com?next=https://other.example/",
    "https://user:password@example.com/login", "https://127.0.0.1:8080/path",
    "https://[::1]:443/", "https://bücher.example/caf%C3%A9",
    "https://xn--bcher-kva.example/", "https://example.com./",
    "https://example.com/a%20b?q=a%2Fb#fragment", " https://example.com/ ",
    "https://example.com/" + "a" * 4980,
], ids=lambda value: value[:50])
def test_supported_url_scans_continue_to_work(api_client, url):
    response = api_client.post("/scans", json={"input_type": "url", "raw_content": url})
    assert response.status_code == 200
    assert response.json()["raw_content"] == url.strip()


def test_malformed_url_inside_text_is_not_rejected_as_a_url_scan(api_client):
    for kind in ("email", "message"):
        assert api_client.post("/scans", json={
            "input_type": kind, "raw_content": "Review this malformed link: https://[bad/login",
        }).status_code == 200


def test_bare_host_scan_preserves_existing_rule_score():
    bare = analyze_scan(ScanCreate(input_type="url", raw_content="verify-bank-login.ru/login"))
    assert bare.risk_score == 80
    assert "Domain Reputation" not in bare.detected_categories


def test_invalid_unicode_url_returns_controlled_error(api_client):
    response = api_client.post(
        "/scans", content=b'{"input_type":"url","raw_content":"https://example.com/\\ud800"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert all(set(error) <= {"type", "loc", "msg"} for error in response.json()["detail"])


def test_invalid_url_error_does_not_echo_private_query(api_client):
    url = "https://[bad/path?token=synthetic-private-token"
    response = api_client.post("/scans", json={"input_type": "url", "raw_content": url})
    assert response.status_code == 422
    assert "synthetic-private-token" not in response.text
