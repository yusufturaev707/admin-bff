"""Alembic migrations match the SQLAlchemy models."""

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import app.auth.models  # noqa: F401  (registers the tables)
from app.core.db import Base, database_url
from app.settings import Settings


async def test_models_and_migrations_agree(settings: Settings) -> None:
    def diff(connection: Connection) -> list[object]:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        return list(compare_metadata(context, Base.metadata))

    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            differences = await conn.run_sync(diff)
    finally:
        await engine.dispose()
    assert differences == []
