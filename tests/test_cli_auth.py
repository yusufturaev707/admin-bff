"""CLI: create-superadmin (section 6) and unlock-login."""

import asyncio
import getpass
import secrets
from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app import cli
from app.auth.lockout import USER_RULE, LoginLimiter
from app.auth.models import AdminUser
from app.auth.passwords import PasswordService
from app.core.db import create_sessionmaker, database_url
from app.settings import Settings
from tests.conftest import Services


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
    for name in ("ARGON2_TIME_COST", "ARGON2_MEMORY_COST_KIB", "ARGON2_PARALLELISM"):
        clean_env.setenv(name, str(getattr(settings, name.lower())))
    yield settings
    asyncio.run(services.reset())


def _passwords(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    replies = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(replies))


async def _load(settings: Settings, username: str) -> AdminUser | None:
    engine = create_async_engine(database_url(settings), poolclass=NullPool)
    try:
        async with create_sessionmaker(engine)() as db:
            user: AdminUser | None = await db.scalar(
                select(AdminUser).where(AdminUser.username == username)
            )
            return user
    finally:
        await engine.dispose()


def test_create_superadmin(cli_env: Settings, clean_env: pytest.MonkeyPatch) -> None:
    password = secrets.token_urlsafe(18)
    _passwords(clean_env, password, password)

    assert cli.main(["create-superadmin", "--username", "Super.Admin"]) == 0

    user = asyncio.run(_load(cli_env, "super.admin"))
    assert user is not None
    assert user.must_change_password is True
    assert user.totp_confirmed_at is None
    assert user.auth_methods == ["password"]
    assert user.password_hash is not None
    assert asyncio.run(PasswordService(cli_env).verify(user.password_hash, password))

    # The same username cannot be created twice.
    _passwords(clean_env, password, password)
    assert cli.main(["create-superadmin", "--username", "super.admin"]) == 1


@pytest.mark.parametrize(
    ("username", "answers", "exit_code"),
    [
        ("ok_admin", ("first-password-1", "second-password-2"), 1),  # mismatch
        ("ok_admin", ("short", "short"), 1),  # policy
        ("ok_admin", ("ok_admin_password", "ok_admin_password"), 1),  # contains username
        ("x", ("whatever-password", "whatever-password"), 2),  # invalid username
    ],
)
def test_create_superadmin_rejects_bad_input(
    cli_env: Settings,
    clean_env: pytest.MonkeyPatch,
    username: str,
    answers: tuple[str, str],
    exit_code: int,
) -> None:
    _passwords(clean_env, *answers)
    assert cli.main(["create-superadmin", "--username", username]) == exit_code
    assert asyncio.run(_load(cli_env, username)) is None


def test_unlock_login(cli_env: Settings, services: Services) -> None:
    async def lock_and_check(unlock: bool) -> int | None:
        redis = services.redis()
        try:
            limiter = LoginLimiter(redis, prefix=services.redis_prefix)
            if not unlock:
                for _ in range(USER_RULE.max_failures):
                    await limiter.record_failure("locked_admin", "10.1.1.1")
            return await limiter.retry_after("locked_admin", "10.2.2.2")
        finally:
            await redis.aclose()

    assert asyncio.run(lock_and_check(unlock=False)) is not None
    assert cli.main(["unlock-login", "--username", "locked_admin"]) == 0
    assert asyncio.run(lock_and_check(unlock=True)) is None
    assert cli.main(["unlock-login"]) == 2
