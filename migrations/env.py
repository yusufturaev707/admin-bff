"""Alembic environment (async, asyncpg).

The connection URL is built from app.settings, so credentials come from the
environment / systemd credentials and are never written to alembic.ini.

Migrations run as DB_USER, the one DB user the service also uses (owner's
decision, 2026-11-24).
"""

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy.engine import URL, Connection
from sqlalchemy.ext.asyncio import create_async_engine

import app.audit.models
import app.auth.models
import app.directory.models
import app.rbac.models  # noqa: F401  (all register their tables on Base.metadata)
from app.audit.models import include_name
from app.core.db import Base, database_url, driver_connect_args
from app.settings import load_settings

config = context.config
if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _target() -> tuple[URL, dict[str, Any]]:
    """The URL and asyncpg connect_args (TLS, PgBouncer)."""
    # Tests pass the URL of their temporary database programmatically.
    url = config.attributes.get("database_url")
    if isinstance(url, URL):
        return url, {}
    settings = load_settings()
    return database_url(settings), driver_connect_args(settings)


def run_migrations_offline() -> None:
    url, _ = _target()
    context.configure(
        url=url.render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url, connect_args = _target()
    engine = create_async_engine(url, connect_args=connect_args)
    async with engine.connect() as connection:
        await connection.run_sync(_run_sync)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
