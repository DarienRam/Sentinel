import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["APP_ENV"] = "test"
os.environ["SECURITY_BACKEND"] = "memory"
os.environ["FRONTEND_ORIGINS"] = '["http://localhost:3000"]'
os.environ["SECRET_KEY"] = "synthetic-test-only-signing-key-0123456789abcdef"

from app.core.database import Base, SessionLocal, engine
from app.main import app


@pytest.fixture(autouse=True)
def reset_database() -> Generator[None, None, None]:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def api_client() -> Generator[TestClient, None, None]:
    with TestClient(app) as client:
        client.headers.update({"Origin": "http://localhost:3000"})
        session = client.post("/auth/anonymous-session")
        assert session.status_code == 200
        client.headers.update({"X-CSRF-Token": session.json()["csrf_token"]})
        yield client
