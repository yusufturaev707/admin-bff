"""Alembic environment (async, asyncpg).

The connection URL is built from app.settings, so credentials come from the
environment / systemd credentials and are never written to alembic.ini.

Migrations run as the schema owner (DB_OWNER_USER, falling back to DB_USER).
When the owner and the application role (DB_USER) differ, the application
role's privileges are (re)granted after every upgrade, in the same transaction
(app/core/db_privileges.py).
"""

import asyncio
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy.engine import URL, Connection
from sqlalchemy.ext.asyncio import create_async_engine

import app.audit.models
import app.auth.models
import app.rbac.models  # noqa: F401  (all register their tables on Base.metadata)
from app.audit.models import include_name
from app.core.db import Base, driver_connect_args, owner_database_url
from app.core.db_privileges import grant_app_privileges
from app.settings import load_settings

config = context.config
if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _target() -> tuple[URL, str | None, dict[str, Any]]:
    """The URL, the application role and asyncpg connect_args (TLS, PgBouncer)."""
    # Tests pass the URL of their temporary database (and optionally the
    # application role) programmatically.
    url = config.attributes.get("database_url")
    if isinstance(url, URL):
        role = config.attributes.get("app_role")
        return url, role if isinstance(role, str) else None, {}
    settings = load_settings()
    owner = settings.db_owner_user
    app_role = settings.db_user if owner is not None and owner != settings.db_user else None
    return owner_database_url(settings), app_role, driver_connect_args(settings)


def run_migrations_offline() -> None:
    url, _, _ = _target()
    context.configure(
        url=url.render_as_string(hide_password=True),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection, app_role: str | None) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()
        if app_role is not None:
            grant_app_privileges(connection, app_role)


async def run_migrations_online() -> None:
    url, app_role, connect_args = _target()
    engine = create_async_engine(url, connect_args=connect_args)
    async with engine.connect() as connection:
        await connection.run_sync(_run_sync, app_role)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
