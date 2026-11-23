"""Test environment (section 12).

Tests run against the local PostgreSQL and Redis:

* PostgreSQL: a temporary database `admin_bff_test_<random>` is created once
  per test session (migrated with Alembic) and dropped at the end. The role
  comes from the usual DB_* settings (environment or `.env`) and needs CREATEDB.
* Redis: a development Redis may be shared with other projects, so nothing is
  flushed. Every test session uses its own random key prefix and deletes only
  the keys under it. TEST_REDIS_URL overrides REDIS_URL.

No secret is written in the tests: keys and passwords are generated randomly.
"""

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import asyncpg
import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from pydantic import SecretStr
from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.audit.sink import AuditEvent, AuditOutcome
from app.core.db import database_url
from app.core.time import utcnow
from app.main import create_app
from app.settings import Settings, load_settings
from tests.helpers import FRONTEND_ORIGIN, app_client

# Env vars that would otherwise leak a developer's local configuration into tests.
_SETTINGS_ENV_VARS = [name.upper() for name in Settings.model_fields] + ["CREDENTIALS_DIRECTORY"]

_HINT = (
    "Testlar lokal PostgreSQL va Redis'ni talab qiladi. .env'dagi DB_* (CREATEDB "
    "huquqli role) va REDIS_URL sozlamalarini tekshiring (README, 'Testlar')."
)


def random_key(size: int = 32) -> SecretStr:
    return SecretStr(base64.b64encode(secrets.token_bytes(size)).decode())


# The audit tables are append-only even for their owner: the partitions are
# dropped instead (DROP fires no trigger; the writer recreates them), and the
# anchors' triggers are switched off for the TRUNCATE. Needs the owner, i.e.
# the role that ran the migrations of the test database.
_RESET_AUDIT_SQL = """
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'audit_log'::regclass LOOP
        EXECUTE format('DROP TABLE %I', r.relname);
    END LOOP;
    IF EXISTS (SELECT 1 FROM audit_anchors) THEN
        ALTER TABLE audit_anchors DISABLE TRIGGER USER;
        TRUNCATE audit_anchors;
        ALTER TABLE audit_anchors ENABLE TRIGGER USER;
    END IF;
END
$$
"""


async def reset_audit(conn: asyncpg.Connection) -> None:
    await conn.execute(_RESET_AUDIT_SQL)


@dataclass(frozen=True)
class Services:
    db_host: str
    db_port: int
    db_user: str
    db_password: SecretStr | None
    db_name: str
    redis_url: str
    redis_password: SecretStr | None
    redis_prefix: str

    async def pg_connect(self, database: str | None = None) -> asyncpg.Connection:
        return await asyncpg.connect(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            password=self.db_password.get_secret_value() if self.db_password else None,
            database=database or self.db_name,
            timeout=5,
        )

    def redis(self) -> Redis:
        return Redis.from_url(
            self.redis_url,
            password=self.redis_password.get_secret_value() if self.redis_password else None,
        )

    async def reset(self) -> None:
        """Empties the test database and this session's Redis keys."""
        conn = await self.pg_connect()
        try:
            await conn.execute("TRUNCATE admin_users, recovery_codes, roles, permissions CASCADE")
            await reset_audit(conn)
        finally:
            await conn.close()
        redis = self.redis()
        try:
            keys = [key async for key in redis.scan_iter(match=f"{self.redis_prefix}*")]
            if keys:
                await redis.delete(*keys)
        finally:
            await redis.aclose()


@pytest.fixture(scope="session")
def services() -> Iterator[Services]:
    base = load_settings()
    svc = Services(
        db_host=base.db_host,
        db_port=base.db_port,
        db_user=base.db_user,
        db_password=base.db_password,
        db_name=f"admin_bff_test_{secrets.token_hex(4)}",
        redis_url=os.environ.get("TEST_REDIS_URL", base.redis_url),
        redis_password=base.redis_password,
        redis_prefix=f"admin-bff-test:{secrets.token_hex(4)}:",
    )

    async def create_database() -> None:
        conn = await svc.pg_connect("postgres")
        try:
            await conn.execute(f'CREATE DATABASE "{svc.db_name}"')
        finally:
            await conn.close()
        redis = svc.redis()
        try:
            await redis.ping()
        finally:
            await redis.aclose()

    try:
        asyncio.run(create_database())
    except (OSError, asyncpg.PostgresError, RedisError) as exc:
        pytest.exit(f"{_HINT} ({type(exc).__name__})", returncode=1)

    config = Config("alembic.ini")
    config.attributes["database_url"] = database_url(base).set(database=svc.db_name)
    config.attributes["skip_logging_config"] = True
    command.upgrade(config, "head")
    try:
        yield svc
    finally:

        async def drop_database() -> None:
            conn = await svc.pg_connect("postgres")
            try:
                await conn.execute(f'DROP DATABASE IF EXISTS "{svc.db_name}" WITH (FORCE)')
            finally:
                await conn.close()

        asyncio.run(drop_database())


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _SETTINGS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def settings(clean_env: pytest.MonkeyPatch, services: Services) -> Settings:
    return Settings(
        _env_file=None,
        app_env="test",
        log_format="json",
        log_level="INFO",
        frontend_origin=FRONTEND_ORIGIN,
        db_host=services.db_host,
        db_port=services.db_port,
        db_user=services.db_user,
        db_password=services.db_password,
        db_name=services.db_name,
        redis_url=services.redis_url,
        redis_password=services.redis_password,
        redis_key_prefix=services.redis_prefix,
        totp_enc_key=random_key(),
        pinfl_hmac_key=random_key(),
        # Fast Argon2 for tests only (production enforces the OWASP minimum).
        argon2_time_cost=1,
        argon2_memory_cost_kib=1024,
        argon2_parallelism=1,
    )


class FakeClock:
    """Injected as the app clock: tests move time instead of sleeping."""

    def __init__(self) -> None:
        self.now = utcnow()

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class AuditRecorder:
    events: list[AuditEvent] = field(default_factory=list)

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    def find(self, action: str, outcome: AuditOutcome | None = None) -> list[AuditEvent]:
        return [
            e
            for e in self.events
            if e.action == action and (outcome is None or e.outcome == outcome)
        ]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def audit() -> AuditRecorder:
    return AuditRecorder()


@pytest.fixture
async def app(
    settings: Settings, clock: FakeClock, audit: AuditRecorder, services: Services
) -> AsyncIterator[FastAPI]:
    yield create_app(settings, clock=clock, audit_listeners=[audit])
    await services.reset()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with app_client(app) as c:
        yield c


@pytest.fixture
def cli_env(
    clean_env: pytest.MonkeyPatch, settings: Settings, services: Services
) -> Iterator[Settings]:
    """The CLI reads settings from the environment, like on a server."""
    clean_env.setenv("APP_ENV", "test")
    clean_env.setenv("LOG_FORMAT", "json")
    clean_env.setenv("DB_HOST", services.db_host)
    clean_env.setenv("DB_PORT", str(services.db_port))
    clean_env.setenv("DB_USER", services.db_user)
    clean_env.setenv("DB_NAME", services.db_name)
    if services.db_password:
        clean_env.setenv("DB_PASSWORD", services.db_password.get_secret_value())
    clean_env.setenv("REDIS_URL", services.redis_url)
    clean_env.setenv("REDIS_KEY_PREFIX", services.redis_prefix)
    assert settings.totp_enc_key is not None
    clean_env.setenv("TOTP_ENC_KEY", settings.totp_enc_key.get_secret_value())
    for name in ("ARGON2_TIME_COST", "ARGON2_MEMORY_COST_KIB", "ARGON2_PARALLELISM"):
        clean_env.setenv(name, str(getattr(settings, name.lower())))
    yield settings
    asyncio.run(services.reset())
