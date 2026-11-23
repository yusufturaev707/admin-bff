"""CLI: create-superadmin (section 6) and unlock-login."""

import asyncio
import base64
import getpass
import secrets

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from app import cli
from app.auth.crypto import SecretBox
from app.auth.lockout import USER_RULE, LoginLimiter
from app.auth.models import AdminUser, AuthMethod
from app.auth.passwords import PasswordService
from app.auth.sessions import SessionStore
from app.core.db import create_sessionmaker, database_url
from app.settings import Settings
from tests.auth_helpers import create_admin
from tests.conftest import FakeClock, Services, random_key


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


def test_reencrypt_totp_after_key_rotation(
    cli_env: Settings, clean_env: pytest.MonkeyPatch, clock: FakeClock
) -> None:
    admin = asyncio.run(create_admin(cli_env, clock))  # encrypted with the old key
    old_key = cli_env.totp_enc_key
    assert old_key is not None
    new_key = random_key()
    clean_env.setenv("TOTP_ENC_KEY", new_key.get_secret_value())
    clean_env.setenv("TOTP_ENC_KEY_PREVIOUS", old_key.get_secret_value())

    assert cli.main(["reencrypt-totp"]) == 0
    assert cli.main(["reencrypt-totp"]) == 0  # idempotent: nothing left to do

    user = asyncio.run(_load(cli_env, admin.username))
    assert user is not None
    assert user.totp_secret_enc is not None
    only_new = SecretBox(base64.b64decode(new_key.get_secret_value()))
    assert only_new.decrypt(user.totp_secret_enc, aad=user.id.bytes).decode() == admin.totp_secret

    # A secret under a key that is not configured is reported, not lost silently.
    clean_env.setenv("TOTP_ENC_KEY", random_key().get_secret_value())
    clean_env.delenv("TOTP_ENC_KEY_PREVIOUS")
    assert cli.main(["reencrypt-totp"]) == 1


def test_reset_totp(cli_env: Settings, clock: FakeClock, services: Services) -> None:
    admin = asyncio.run(create_admin(cli_env, clock))
    other = asyncio.run(create_admin(cli_env, clock))

    async def open_session() -> None:
        redis = services.redis()
        store = SessionStore(
            redis,
            prefix=services.redis_prefix,
            idle_timeout_s=1800,
            absolute_timeout_s=43200,
            clock=clock,
        )
        await store.create(
            user_id=admin.id,
            username=admin.username,
            auth_method=AuthMethod.PASSWORD,
            ip="10.0.0.1",
            user_agent="test",
            mfa_at=clock(),
            pending=(),
            perm_version=0,
        )
        await redis.aclose()

    async def session_count() -> int:
        redis = services.redis()
        try:
            store = SessionStore(
                redis,
                prefix=services.redis_prefix,
                idle_timeout_s=1800,
                absolute_timeout_s=43200,
                clock=clock,
            )
            return len(await store.list_for_user(admin.id))
        finally:
            await redis.aclose()

    asyncio.run(open_session())
    assert asyncio.run(session_count()) == 1

    assert cli.main(["reset-totp", "--all"]) == 2  # needs --yes
    assert cli.main(["reset-totp"]) == 2
    assert cli.main(["reset-totp", "--username", "nobody_here"]) == 1

    assert cli.main(["reset-totp", "--username", admin.username]) == 0
    reset = asyncio.run(_load(cli_env, admin.username))
    kept = asyncio.run(_load(cli_env, other.username))
    assert reset is not None
    assert kept is not None
    assert reset.totp_secret_enc is None
    assert reset.totp_confirmed_at is None
    assert kept.totp_enabled
    assert asyncio.run(session_count()) == 0

    assert cli.main(["reset-totp", "--all", "--yes"]) == 0
    cleared = asyncio.run(_load(cli_env, other.username))
    assert cleared is not None
    assert not cleared.totp_enabled
