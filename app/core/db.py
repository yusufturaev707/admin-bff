"""Admin DB (PostgreSQL 16+, SQLAlchemy 2 async + asyncpg).

Only the BFF's own database. Databases of other systems are never connected
to (architecture decision 3): they are reached through their internal admin API.
"""

import ssl
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import DateTime, MetaData, text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.settings import DB_VERIFYING_SSLMODES, Settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    # Every `Mapped[datetime]` column is `timestamptz` (timezone-aware UTC).
    type_annotation_map: ClassVar[dict[Any, Any]] = {datetime: DateTime(timezone=True)}


def database_url(settings: Settings) -> URL:
    """The one DB user (DB_USER): the migrations and the service share it
    (owner's decision, 2026-11-24)."""
    return URL.create(
        drivername="postgresql+asyncpg",
        username=settings.db_user,
        password=settings.db_password.get_secret_value() if settings.db_password else None,
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def db_ssl_context(settings: Settings) -> ssl.SSLContext | None:
    """The verifying TLS context (verify-ca, verify-full), None otherwise.

    Both modes require a certificate signed by DB_SSLROOTCERT (or a system
    CA); verify-full also requires it to be issued for DB_HOST (a DNS name or
    an IP address in subjectAltName). The server refusing TLS is an error,
    never a silent fallback to plain text."""
    if settings.db_tls_mode not in DB_VERIFYING_SSLMODES:
        return None
    context = ssl.create_default_context(cafile=settings.db_sslrootcert)
    context.check_hostname = settings.db_tls_mode == "verify-full"
    return context


def ssl_connect_args(settings: Settings) -> dict[str, Any]:
    """asyncpg `connect_args` for TLS (`Settings.db_tls_mode`); shared by the
    app and the migrations.

    `disable` passes `ssl=False`, since asyncpg's own default for TCP is
    "prefer". "prefer" is asyncpg's mode: TLS without a certificate check when
    the server offers it, plain text when it does not."""
    mode = settings.db_tls_mode
    if mode == "disable":
        return {"ssl": False}
    if mode == "prefer":
        return {"ssl": "prefer"}
    return {"ssl": db_ssl_context(settings)}


def _prepared_statement_name() -> str:
    return f"__asyncpg_{uuid4().hex}__"


def driver_connect_args(settings: Settings) -> dict[str, Any]:
    """asyncpg `connect_args` shared by the app and the migrations: TLS
    (`ssl_connect_args`) and PgBouncer.

    PgBouncer in transaction or statement pool mode gives each transaction
    any server connection. asyncpg's numbered statement names
    (`__asyncpg_stmt_1__`) then collide with those another client left on it:
    "prepared statement ... already exists". Unique names and no statement
    caches work through PgBouncer and directly alike; re-preparing every
    statement costs the admin panel nothing noticeable."""
    return {
        **ssl_connect_args(settings),
        "statement_cache_size": 0,
        "prepared_statement_cache_size": 0,
        "prepared_statement_name_func": _prepared_statement_name,
    }


def create_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(
        database_url(settings),
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "timeout": 5,
            # Every session works in UTC regardless of the server's timezone.
            # PgBouncer passes both parameters on to the server connection.
            "server_settings": {"application_name": "admin-bff", "timezone": "UTC"},
            **driver_connect_args(settings),
        },
    )


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


@lru_cache(maxsize=1)
def migration_heads() -> frozenset[str]:
    """The revisions the code expects (the heads of migrations/)."""
    return frozenset(ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_heads())


async def database_revision(engine: AsyncEngine) -> str | None:
    """The revision the database is at; None if it was never migrated."""
    async with engine.connect() as conn:
        if await conn.scalar(text("SELECT to_regclass('alembic_version')")) is None:
            return None
        revision = await conn.scalar(text("SELECT version_num FROM alembic_version"))
    return revision if isinstance(revision, str) else None


async def connection_is_encrypted(engine: AsyncEngine) -> bool:
    """Whether the BFF's own link to the database server uses TLS ("prefer"
    may fall back to plain text).

    Read from the client side: behind PgBouncer, `pg_stat_ssl` would describe
    PgBouncer's link to PostgreSQL instead."""
    async with engine.connect() as conn:
        raw = await conn.get_raw_connection()
        # asyncpg keeps the (TLS-upgraded) asyncio transport here.
        transport = getattr(raw.driver_connection, "_transport", None)
    return transport is not None and transport.get_extra_info("ssl_object") is not None


async def ping_database(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
