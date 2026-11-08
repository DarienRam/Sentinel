import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core.resource_protection import ResourceProtectionMiddleware, actor_rules, opaque_key
from app.core.security_store import (
    AnonymousSession, BudgetExceeded, MemorySecurityStore, RedisSecurityStore,
    SecurityUnavailable, create_security_store,
)


def test_atomic_concurrent_quota_and_recovery():
    clock = [1000.0]
    store = MemorySecurityStore(clock=lambda: clock[0])

    def attempt(_):
        try:
            store.check([("shared", 7, 60)])
            return True
        except BudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=20) as pool:
        assert sum(pool.map(attempt, range(100))) == 7
    with pytest.raises(BudgetExceeded) as error:
        store.check([("shared", 7, 60)])
    assert error.value.retry_after == 60
    clock[0] += 60
    assert attempt(None)


def test_multi_bucket_admission_is_atomic_and_bounded():
    store = MemorySecurityStore(max_entries=2)
    store.check([("a", 1, 60)])
    with pytest.raises(BudgetExceeded):
        store.check([("b", 1, 60), ("a", 1, 60)])
    assert "b" not in store.counters
    store.check([("b", 1, 60)])
    with pytest.raises(SecurityUnavailable):
        store.check([("c", 1, 60)])


def test_concurrency_leases_are_atomic_and_released():
    store = MemorySecurityStore()
    token = store.acquire("requests", 1)
    with pytest.raises(BudgetExceeded):
        store.acquire("requests", 1)
    store.release("requests", token)
    assert store.acquire("requests", 1)


@pytest.mark.parametrize("path,limit", [("/auth/register", 10), ("/auth/login", 20),
                                      ("/auth/anonymous-session", 30)])
def test_endpoint_specific_ip_limits_and_forwarded_spoofing(api_client, path, limit):
    from app.main import app

    # Reset only synthetic security counters, never a real database.
    app.state.security_store.counters.clear()
    for i in range(limit):
        response = api_client.post(path, json={}, headers={"X-Forwarded-For": f"192.0.2.{i}",
                                                         "Forwarded": f"for=192.0.2.{i}"})
        assert response.status_code != 429
    response = api_client.post(path, json={})
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0
    assert response.json()["retry_after"] == int(response.headers["retry-after"])


def test_anonymous_actor_quota_survives_rotation(api_client):
    from app.main import app
    from app.core.anonymous_sessions import read_session, cookie_name
    from app.core.security_store import credential_key

    store = app.state.security_store
    session = store.load_session(credential_key(api_client.cookies.get(cookie_name())))
    key = opaque_key("scan-day", session.owner)
    store.check([(key, 1, 86400)])
    # Set synthetic usage at the real configured 30/day ceiling.
    store.counters[key] = (30, store.clock() + 86400)
    rotated = api_client.post("/auth/anonymous-session/rotate")
    api_client.headers["X-CSRF-Token"] = rotated.json()["csrf_token"]
    response = api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic budget test."})
    assert response.status_code == 429
    assert api_client.get("/scans").json() == []


def test_account_scan_quota_and_ip_exhaustion_recovery(api_client, db_session):
    from app.main import app
    from app.core.account_sessions import issue_account_session
    from app.models.user import User

    user = User(username="quota-user", email="quota@example.com", password_hash="synthetic-unused-hash")
    db_session.add(user)
    db_session.commit()
    token, _ = issue_account_session(SimpleNamespace(app=app), user)
    headers = {"Authorization": "Bearer " + token}
    store = app.state.security_store
    key = opaque_key("scan-day", "user:" + str(user.id))
    store.counters[key] = (100, store.clock() + 86400)
    payload = {"input_type": "message", "raw_content": "Synthetic budget test."}
    assert api_client.post("/scans", json=payload, headers=headers).status_code == 429
    store.counters[key] = (100, store.clock() - 1)
    assert api_client.post("/scans", json=payload, headers=headers).status_code == 200


@pytest.mark.parametrize("group,path,method,payload", [
    ("feedback", "/scans/999/feedback", "post", {"feedback": "Correct"}),
    ("read", "/scans/analytics/summary", "get", None),
    ("read", "/scans", "get", None),
])
def test_actor_mutation_and_read_limits(api_client, group, path, method, payload):
    from app.main import app
    from app.core.anonymous_sessions import cookie_name
    from app.core.security_store import credential_key

    store = app.state.security_store
    owner = store.load_session(credential_key(api_client.cookies.get(cookie_name()))).owner
    ceiling = 60 if group == "read" else 20
    store.counters[opaque_key("actor:" + group, owner)] = (ceiling, store.clock() + 60)
    response = api_client.request(method, path, json=payload) if payload else api_client.get(path)
    assert response.status_code == 429


def test_non_json_error_payloads_are_controlled(api_client):
    # A syntactically valid JSON integer beyond Python's digit conversion budget.
    response = api_client.post("/scans", content=b"9" * 6000, headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 422)


def test_store_failure_is_503_without_creating_scan(api_client, monkeypatch):
    from app.main import app
    from app.models.scan import Scan
    from app.core.database import SessionLocal
    from sqlalchemy import func, select

    def unavailable(*args, **kwargs):
        raise SecurityUnavailable()
    monkeypatch.setattr(app.state.security_store, "check", unavailable)
    response = api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic failure test."})
    assert response.status_code == 503
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Scan)) == 0


@pytest.mark.parametrize("content,headers,status", [
    (b"x" * 65537, {}, 413),
    (b"{}", {"Content-Length": "999999"}, 413),
    (b"{}", {"Content-Length": "-1"}, 400),
    (b"{}", {"Content-Length": "9" * 5000}, 413),
    (b"\xff", {"Content-Type": "application/json"}, 400),
    (b"{" , {"Content-Type": "application/json"}, 422),
    (b"[" * 1000 + b"]" * 1000, {"Content-Type": "application/json"}, 413),
])
def test_body_and_json_budgets(api_client, content, headers, status):
    assert api_client.post("/scans", content=content, headers=headers).status_code == status
    assert api_client.get("/scans").json() == []


def test_request_target_and_header_budgets(api_client):
    assert api_client.get("/scans?x=" + "a" * 5000).status_code == 414
    assert api_client.get("/scans", headers={"X-Test": "a" * 17000}).status_code == 431


def test_streamed_body_cannot_bypass_declared_length_or_timeout():
    from app.core.config import settings

    async def run(messages, slow=False):
        captured = []
        async def downstream(scope, receive, send):
            raise AssertionError("Oversized/slow body reached application")
        async def receive():
            if slow:
                await asyncio.sleep(1)
            return messages.pop(0)
        async def send(message):
            captured.append(message)
        scope = {"type": "http", "method": "POST", "path": "/unrouted", "raw_path": b"/unrouted",
                 "headers": [(b"content-length", b"1")], "query_string": b"",
                 "app": SimpleNamespace(state=SimpleNamespace()), "client": ("test", 1)}
        await ResourceProtectionMiddleware(downstream)(scope, receive, send)
        return captured[0]["status"]

    assert asyncio.run(run([{"type": "http.request", "body": b"x" * 40000, "more_body": True},
                            {"type": "http.request", "body": b"y" * 40000}])) == 413
    previous = settings.request_body_timeout_seconds
    try:
        settings.request_body_timeout_seconds = 0.01
        assert asyncio.run(run([], slow=True)) == 408
    finally:
        settings.request_body_timeout_seconds = previous


def test_history_and_summary_have_default_result_bound(api_client, db_session):
    from app.main import app
    from app.models.scan import Scan
    from app.core.anonymous_sessions import cookie_name
    from app.core.security_store import credential_key

    owner = app.state.security_store.load_session(credential_key(api_client.cookies.get(cookie_name()))).owner
    for i in range(105):
        db_session.add(Scan(anonymous_session_id=owner, input_type="message", raw_content="Synthetic history.",
                            risk_score=0, confidence_score=80, risk_level="Low", summary="Synthetic",
                            recommendation="Review", is_saved=False))
    db_session.commit()
    assert len(api_client.get("/scans").json()) == 100
    assert api_client.get("/scans/analytics/summary").json()["total_scans"] == 100


def test_production_memory_backend_and_missing_redis_fail_closed():
    key = "8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB"
    production = Settings(_env_file=None, app_env="production", secret_key=key)
    with pytest.raises(RuntimeError, match="Redis"):
        create_security_store(production)
    production.security_backend = "redis"
    with pytest.raises(RuntimeError, match="Redis"):
        create_security_store(production)


def test_production_unavailable_redis_fails_before_database_start(monkeypatch):
    from app.core import security_store
    from app import main

    class BrokenRedis:
        def __init__(self, *args, **kwargs):
            raise SecurityUnavailable()
    monkeypatch.setattr(security_store, "RedisSecurityStore", BrokenRedis)
    production = Settings(_env_file=None, app_env="production", secret_key="8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB",
                          security_backend="redis", redis_url="redis://unused-test-host",
                          frontend_origins=["https://app.example.com"])
    def forbidden_database_start():
        raise AssertionError("Database must not be touched when security infrastructure is unavailable")
    monkeypatch.setattr(main, "settings", production)
    monkeypatch.setattr(main, "init_db", forbidden_database_start)
    async def startup():
        async with main.lifespan(main.app):
            pass
    with pytest.raises(RuntimeError, match="refusing startup"):
        asyncio.run(startup())


@pytest.mark.parametrize("origin", ["http://app.example.com", "https://*", "https://app.example.com/",
                                   "https://app.example.com/path", "https://user:pass@app.example.com",
                                   "https://app.example.com:bad"])
def test_production_requires_exact_https_frontend_origin(origin):
    production = Settings(_env_file=None, app_env="production", secret_key="8rK2vD9!aZ5#tP7xQ1mW4sJ6nL3hF0cB",
                          security_backend="redis", redis_url="redis://unused-test-host",
                          frontend_origins=[origin])
    with pytest.raises(RuntimeError, match="HTTPS"):
        create_security_store(production)


def test_redis_adapter_failure_hides_connection_secrets():
    class BrokenRedis:
        def ping(self):
            raise RuntimeError("synthetic-sensitive-connection-string")
    with pytest.raises(SecurityUnavailable) as error:
        RedisSecurityStore(client=BrokenRedis())
    assert "synthetic-sensitive" not in str(error.value)


def test_redis_admission_is_one_atomic_script_with_same_cluster_slot():
    class Client:
        args = None
        def ping(self):
            return True
        def eval(self, *args):
            self.args = args
            return 17
    client = Client()
    store = RedisSecurityStore(client=client)
    with pytest.raises(BudgetExceeded) as error:
        store.check([("ip", 10, 60), ("actor", 20, 60)])
    assert error.value.retry_after == 17
    assert client.args[1] == 2
    assert all("{security}" in key for key in client.args[2:4])
