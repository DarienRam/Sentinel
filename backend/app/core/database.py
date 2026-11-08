import threading
from contextlib import nullcontext

from sqlalchemy import create_engine, inspect, text
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings


engine_kwargs = {}
if settings.database_url.startswith("sqlite"):
    engine_kwargs = {
        "connect_args": {"check_same_thread": False},
    }

if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
    engine_kwargs["poolclass"] = StaticPool
engine = create_engine(settings.database_url, hide_parameters=True, **engine_kwargs)
_memory_connection_lock = threading.Lock()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    # A disposable :memory: database shares one DBAPI connection. Serialize whole
    # request transactions there; file databases use SQLAlchemy's normal pool.
    guard = _memory_connection_lock if isinstance(engine.pool, StaticPool) else nullcontext()
    with guard:
        db = SessionLocal()
        try:
            yield db
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(status_code=503, detail="Database service unavailable.") from None
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()


def init_db() -> None:
    from app import models  # noqa: F401

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if settings.app_env == "production":
        if "alembic_version" not in tables:
            raise RuntimeError("Production requires an explicitly reviewed Alembic migration before startup.")
        with engine.connect() as connection:
            versions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
        if versions != ["0002"]:
            raise RuntimeError("Database migration revision is not current; startup refused.")
    if not tables and settings.app_env != "production":
        Base.metadata.create_all(bind=engine)
        return
    # Existing databases are inspected for shape only; startup never ALTERs them.
    for table in Base.metadata.sorted_tables:
        if table.name not in tables or not {c.name for c in table.columns} <= {
            c["name"] for c in inspector.get_columns(table.name)
        }:
            raise RuntimeError("Database schema requires a separately approved migration; no automatic upgrade performed.")
