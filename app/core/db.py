"""Admin DB (PostgreSQL 16+, SQLAlchemy 2 async + asyncpg).

Only the BFF's own database. Databases of other systems are never connected
to (architecture decision 3): they are reached through their internal admin API.
"""

import ssl
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar

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

from app.settings import Settings

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
    """The application role (DB_USER)."""
    return URL.create(
        drivername="postgresql+asyncpg",
        username=settings.db_user,
        password=settings.db_password.get_secret_value() if settings.db_password else None,
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def owner_database_url(settings: Settings) -> URL:
    """The schema owner (DB_OWNER_USER) for migrations; DB_USER if unset."""
    if settings.db_owner_user is None:
        return database_url(settings)
    password = settings.db_owner_password
    return database_url(settings).set(
        username=settings.db_owner_user,
        password=password.get_secret_value() if password else None,
    )


def db_ssl_context(settings: Settings) -> ssl.SSLContext | None:
    """TLS for the connection to PostgreSQL (DB_SSLMODE), None for disable.

    Both modes require a certificate signed by DB_SSLROOTCERT (or a system
    CA); verify-full also requires it to be issued for DB_HOST (a DNS name or
    an IP address in subjectAltName). The server refusing TLS is an error,
    never a silent fallback to plain text."""
    if settings.db_sslmode == "disable":
        return None
    context = ssl.create_default_context(cafile=settings.db_sslrootcert)
    context.check_hostname = settings.db_sslmode == "verify-full"
    return context


def ssl_connect_args(settings: Settings) -> dict[str, Any]:
    """asyncpg `connect_args` for TLS; shared by the app and the migrations.

    `disable` passes `ssl=False`: without it asyncpg would "prefer" TLS and
    accept any certificate, which looks encrypted but is not verified."""
    context = db_ssl_context(settings)
    return {"ssl": False if context is None else context}


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
            "server_settings": {"application_name": "admin-bff", "timezone": "UTC"},
            **ssl_connect_args(settings),
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


async def ping_database(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
