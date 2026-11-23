"""Admin DB (PostgreSQL 16+, SQLAlchemy 2 async + asyncpg).

Only the BFF's own database. Databases of other systems are never connected
to (architecture decision 3): they are reached through their internal admin API.
"""

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
