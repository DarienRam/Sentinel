"""Explicit-target migrations; no .env loading or default database connection."""
import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.exc import SQLAlchemyError

config = context.config
if context.is_offline_mode():
    raise RuntimeError("Offline migrations are disabled; use a reviewed explicit database target.")


def run(connection):
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:
    run(connection)
else:
    url = os.environ.get("MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("MIGRATION_DATABASE_URL is required; no development database default is used.")
    engine = None
    try:
        engine = create_engine(url, poolclass=NullPool, hide_parameters=True)
        with engine.connect() as connection:
            run(connection)
    except (SQLAlchemyError, ValueError):
        raise RuntimeError("Migration database operation failed; connection details are suppressed.") from None
    finally:
        if engine is not None:
            engine.dispose()
