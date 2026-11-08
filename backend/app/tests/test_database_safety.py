from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.auth import register_user
from app.core.database import Base
from app.models import Scan, ScanFeedback, ScanFinding, User
from app.schemas.auth import UserRegister
from app.services.retention import purge_expired_batch


def test_registration_race_loser_rolls_back_and_session_is_reusable():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    payload = UserRegister(username="race", email="race@example.com", password="synthetic-password")
    with Session(engine) as first, Session(engine) as second:
        # Force the exact interleaving: both prechecks observe no existing user;
        # the database uniqueness constraint decides the later commit.
        first.scalar = lambda *args, **kwargs: None
        second.scalar = lambda *args, **kwargs: None
        assert register_user(payload, first).username == "race"
        with pytest.raises(HTTPException) as error:
            register_user(payload, second)
        assert error.value.status_code == 409
        assert len(second.scalars(select(User)).all()) == 1
    engine.dispose()


def test_database_errors_are_redacted_and_failed_scan_is_rolled_back(api_client, monkeypatch):
    from app.core.database import SessionLocal
    original = Session.commit
    def broken(db):
        if any(isinstance(obj, Scan) for obj in db.new):
            db.flush()
            raise OperationalError("synthetic-private-sql", {"secret": "synthetic-private-value"}, Exception("private database error"))
        return original(db)
    monkeypatch.setattr(Session, "commit", broken)
    response = api_client.post("/scans", json={"input_type": "message", "raw_content": "Synthetic private submission."})
    assert response.status_code == 503
    assert response.json() == {"detail": "Database service unavailable."}
    with SessionLocal() as db:
        assert db.scalars(select(Scan)).all() == []


def synthetic_scan(owner, expiry, saved=False):
    return Scan(anonymous_session_id=owner, input_type="message", raw_content="Synthetic privacy fixture.",
                risk_score=0, confidence_score=80, risk_level="Low", summary="Synthetic", recommendation="Review",
                is_saved=saved, expires_at=expiry,
                feedback=ScanFeedback(label="Correct", note="Synthetic note"),
                findings=[ScanFinding(category="Test", severity="Low", message="Synthetic finding")])


def test_retention_deletes_only_expired_temporary_scans_and_children(db_session):
    now = datetime.now(timezone.utc)
    rows = [synthetic_scan("owner-a", now-timedelta(days=1)),
            synthetic_scan("owner-b", now+timedelta(days=1)),
            synthetic_scan("owner-c", None, True),
            synthetic_scan("owner-d", now-timedelta(days=1), True)]
    db_session.add_all(rows)
    db_session.commit()
    keep_ids = [r.id for r in rows[1:]]
    assert purge_expired_batch(db_session, now=now) == 1
    assert list(db_session.scalars(select(Scan.id).order_by(Scan.id))) == keep_ids
    assert len(db_session.scalars(select(ScanFeedback)).all()) == 3
    assert len(db_session.scalars(select(ScanFinding)).all()) == 3


def test_retention_is_bounded_and_rolls_back(db_session, monkeypatch):
    db_session.add_all([synthetic_scan("owner", datetime.now(timezone.utc)-timedelta(days=1)) for _ in range(3)])
    db_session.commit()
    assert purge_expired_batch(db_session, batch_size=1) == 1
    def broken():
        db_session.flush()
        raise OperationalError("private", {}, Exception("private"))
    monkeypatch.setattr(db_session, "commit", broken)
    with pytest.raises(OperationalError):
        purge_expired_batch(db_session)
    assert len(db_session.scalars(select(Scan)).all()) == 2


def migration_config(connection):
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.attributes["connection"] = connection
    return config


def test_migration_fresh_and_index_upgrade_preserve_synthetic_records():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        config = migration_config(connection)
        command.upgrade(config, "0001")
        connection.execute(text("INSERT INTO users (username,email,password_hash) VALUES ('fixture','fixture@example.com','synthetic-hash')"))
        command.upgrade(config, "head")
        assert connection.scalar(text("SELECT password_hash FROM users")) == "synthetic-hash"
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0002"
        assert {i["name"] for i in inspect(connection).get_indexes("scans")} >= {"ix_scans_user_created", "ix_scans_anon_created", "ix_scans_expiry"}
        command.downgrade(config, "0001")
        assert connection.scalar(text("SELECT count(*) FROM users")) == 1
    engine.dispose()


def test_migration_refuses_unreviewed_existing_database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        with pytest.raises(RuntimeError, match="schema review"):
            command.upgrade(migration_config(connection), "head")
    engine.dispose()


def test_startup_does_not_alter_existing_incomplete_schema(monkeypatch):
    from app.core import database
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
    monkeypatch.setattr(database, "engine", engine)
    with pytest.raises(RuntimeError, match="approved migration"):
        database.init_db()
    assert [c["name"] for c in inspect(engine).get_columns("users")] == ["id"]
    assert inspect(engine).get_table_names() == ["users"]
    engine.dispose()


def test_retention_cli_requires_explicit_target_and_apply_confirmation(monkeypatch):
    from app.retention import main
    monkeypatch.delenv("RETENTION_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit):
        main([])
    monkeypatch.setenv("RETENTION_DATABASE_URL", "sqlite:///:memory:")
    with pytest.raises(SystemExit):
        main(["--apply"])


def test_production_startup_requires_versioned_schema_even_with_current_tables(monkeypatch):
    from app.core import database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database.settings, "app_env", "production")
    with pytest.raises(RuntimeError, match="Alembic migration"):
        database.init_db()
    assert "alembic_version" not in inspect(engine).get_table_names()
    engine.dispose()


def test_retention_bad_connection_config_is_redacted(monkeypatch, capsys):
    from app.retention import main
    monkeypatch.setenv("RETENTION_DATABASE_URL", "synthetic-private-invalid-url")
    assert main([]) == 1
    captured = capsys.readouterr()
    assert "synthetic-private" not in captured.err
    assert "operation failed" in captured.err
