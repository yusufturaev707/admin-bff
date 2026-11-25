"""The admin DB may sit behind PgBouncer in transaction pool mode.

There every transaction may get another server connection, which still holds
the prepared statements other clients made. asyncpg's numbered names
(`__asyncpg_stmt_1__`) then collide: "prepared statement ... already exists".
"""

import re

import asyncpg.connection
import pytest
from sqlalchemy import text

from app.core import db
from app.settings import Settings


def test_connect_args_avoid_statement_name_collisions(clean_env: pytest.MonkeyPatch) -> None:
    args = db.driver_connect_args(Settings(_env_file=None, app_env="test"))
    assert args["statement_cache_size"] == 0
    assert args["prepared_statement_cache_size"] == 0
    name = args["prepared_statement_name_func"]
    assert name() != name()
    assert args["ssl"] is False  # the TLS part is still there


async def test_statements_are_prepared_under_unique_names(settings: Settings) -> None:
    engine = db.create_engine(settings)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            names = (
                (await conn.execute(text("SELECT name FROM pg_prepared_statements")))
                .scalars()
                .all()
            )
    finally:
        await engine.dispose()
    assert names
    assert all(re.fullmatch(r"__asyncpg_[0-9a-f]{32}__", n) for n in names), names


async def test_a_taken_numbered_name_does_not_matter(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What PgBouncer does: the server connection already has the name that
    asyncpg would pick next (its process-wide counter restarts at 1)."""
    engine = db.create_engine(settings)
    try:
        async with engine.connect() as conn:
            raw = await conn.get_raw_connection()
            assert raw.driver_connection is not None
            # Simple query protocol: asyncpg prepares nothing for it.
            await raw.driver_connection.execute('PREPARE "__asyncpg_stmt_1__" AS SELECT 1')
            monkeypatch.setattr(asyncpg.connection, "_uid", 0)
            assert await conn.scalar(text("SELECT 42")) == 42
    finally:
        await engine.dispose()


async def test_plain_text_link_is_reported(settings: Settings) -> None:
    engine = db.create_engine(settings.model_copy(update={"db_sslmode": "disable"}))
    try:
        assert await db.connection_is_encrypted(engine) is False
    finally:
        await engine.dispose()
