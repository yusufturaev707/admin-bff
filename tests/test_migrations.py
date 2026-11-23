"""Alembic migrations match the SQLAlchemy models."""

import asyncio
import secrets

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import app.audit.models
import app.auth.models
import app.rbac.models  # noqa: F401  (all register their tables)
from app.audit.models import include_name
from app.core.db import Base, database_url
from app.settings import Settings, load_settings
from tests.conftest import Services


async def test_models_and_migrations_agree(settings: Settings) -> None:
    def diff(connection: Connection) -> list[object]:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "include_name": include_name}
        )
        return list(compare_metadata(context, Base.metadata))

    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            differences = await conn.run_sync(diff)
    finally:
        await engine.dispose()
    assert differences == []


def test_audit_migration_downgrades_and_upgrades_again(services: Services) -> None:
    """On a database of its own: head -> 0002 -> head."""
    name = f"admin_bff_test_mig_{secrets.token_hex(4)}"

    async def admin(sql: str) -> None:
        conn = await services.pg_connect("postgres")
        try:
            await conn.execute(sql)
        finally:
            await conn.close()

    async def tables() -> set[str]:
        conn = await services.pg_connect(name)
        try:
            rows = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
            )
            return {r["tablename"] for r in rows}
        finally:
            await conn.close()

    asyncio.run(admin(f'CREATE DATABASE "{name}"'))
    try:
        config = Config("alembic.ini")
        config.attributes["database_url"] = database_url(load_settings()).set(database=name)
        config.attributes["skip_logging_config"] = True
        command.upgrade(config, "head")
        assert {"audit_log", "audit_anchors"} <= asyncio.run(tables())
        command.downgrade(config, "0002")
        assert not {"audit_log", "audit_anchors"} & asyncio.run(tables())
        command.upgrade(config, "head")
        assert "audit_anchors" in asyncio.run(tables())
    finally:
        asyncio.run(admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
