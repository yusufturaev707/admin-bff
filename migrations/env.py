"""Alembic environment (async, asyncpg).

The connection URL is built from app.settings, so credentials come from the
environment / systemd credentials and are never written to alembic.ini.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.db import Base, database_url
from app.settings import load_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Models register themselves on Base.metadata when imported (Phase 1+).
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = database_url(load_settings()).render_as_string(hide_password=True)
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(database_url(load_settings()))
    async with engine.connect() as connection:
        await connection.run_sync(_run_sync)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
