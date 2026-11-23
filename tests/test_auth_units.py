"""Unit tests: crypto, password policy, TOTP, recovery codes, auth settings."""

import asyncio
import base64
import secrets
import threading
import time

import pytest
from argon2 import PasswordHasher
from pydantic import SecretStr, ValidationError

from app.auth.lockout import BUSY_RETRY_AFTER_S, LoginLimiter
from app.auth.models import normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.settings import Settings
from tests.conftest import Services, random_key


@pytest.mark.parametrize(
    ("password", "reason"),
    [
        ("Short1!", "password_too_short"),
        ("x" * 257, "password_too_long"),
        ("my-Operator-2026", "password_contains_username"),
        ("qwertyuiopasdfgh", "password_too_common"),
        ("UZBEKISTAN2026", "password_too_common"),
    ],
)
def test_password_policy_rejects(password: str, reason: str) -> None:
    with pytest.raises(PasswordPolicyError) as exc_info:
        check_password_policy(password, username="operator")
    assert exc_info.value.reason == reason


def test_password_policy_accepts_a_long_random_password() -> None:
    check_password_policy(secrets.token_urlsafe(16), username="operator")


async def test_password_hashing(settings: Settings) -> None:
    service = PasswordService(settings)
    password = secrets.token_urlsafe(16)
    hashed = await service.hash(password)
    assert hashed.startswith("$argon2id$")
    assert await service.verify(hashed, password)
    assert not await service.verify(hashed, password + "x")
    assert not await service.verify("not-a-hash", password)
    # Unknown user: a dummy hash is verified and the answer is always False.
    assert not await service.verify(None, password)


def test_weaker_argon2_parameters_mean_rehash(settings: Settings) -> None:
    weak = PasswordService(settings)
    strong = PasswordService(settings.model_copy(update={"argon2_time_cost": 2}))
    assert strong.needs_rehash(weak._hasher.hash("x"))


class _SlowHasher:
    """Wraps the real hasher and records how many hashes run at once."""

    def __init__(self, inner: PasswordHasher) -> None:
        self._inner = inner
        self._guard = threading.Lock()
        self.running = 0
        self.peak = 0

    def hash(self, password: str) -> str:
        with self._guard:
            self.running += 1
            self.peak = max(self.peak, self.running)
        time.sleep(0.05)
        with self._guard:
            self.running -= 1
        return self._inner.hash(password)


async def test_argon2_checks_at_once_are_bounded(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each check holds ARGON2_MEMORY_COST_KIB; a burst must not run one per thread.
    service = PasswordService(settings.model_copy(update={"argon2_max_concurrency": 2}))
    slow = _SlowHasher(service._hasher)
    monkeypatch.setattr(service, "_hasher", slow)
    await asyncio.gather(*(service.hash(secrets.token_urlsafe(16)) for _ in range(6)))
    assert slow.peak == 2


async def test_login_limiter_reservations(services: Services) -> None:
    redis = services.redis()
    prefix = f"{services.redis_prefix}limiter:"
    limiter = LoginLimiter(redis, prefix=prefix)
    user, ip = "someone", "10.0.0.1"
    try:
        for _ in range(5):
            assert await limiter.acquire(user, ip) is None
        # Five checks still running take up the username's limit.
        assert await limiter.acquire(user, ip) == BUSY_RETRY_AFTER_S
        # One ends with an error, not a wrong guess: its slot is free again.
        assert await limiter.finish(user, ip, failed=False) == []
        assert await limiter.acquire(user, ip) is None
        # The five others fail: the fifth failure locks the username, once.
        created = []
        for _ in range(5):
            created += [rule.name for rule in await limiter.finish(user, ip, failed=True)]
        assert created == ["user"]
        retry_after = await limiter.acquire(user, ip)
        assert retry_after is not None
        assert retry_after > BUSY_RETRY_AFTER_S
        # Another username from the same IP is not affected (the IP has 5 of 20).
        assert await limiter.acquire("someone_else", ip) is None
    finally:
        keys = [key async for key in redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await redis.delete(*keys)
        await redis.aclose()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Operator_1", "operator_1"),
        ("  a.b-c ", "a.b-c"),
        ("ab", None),
        ("bad name", None),
        ("-x1", None),
    ],
)
def test_normalize_username(raw: str, expected: str | None) -> None:
    assert normalize_username(raw) == expected


def test_auth_keys_are_validated(clean_env: pytest.MonkeyPatch) -> None:
    for bad in ("not base64!", base64.b64encode(b"short").decode()):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, app_env="test", pinfl_hmac_key=SecretStr(bad))
    assert len(Settings(_env_file=None, pinfl_hmac_key=random_key()).pinfl_key()) == 32
    with pytest.raises(RuntimeError, match="PINFL_HMAC_KEY"):
        Settings(_env_file=None, app_env="test").pinfl_key()


def test_production_refuses_weak_argon2(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="Argon2id"):
        Settings(_env_file=None, argon2_memory_cost_kib=1024)
    assert Settings(_env_file=None).argon2_memory_cost_kib == 64 * 1024


def test_redis_key_prefix_is_validated(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, redis_key_prefix="bad prefix*")
    assert Settings(_env_file=None, redis_key_prefix="dev:admin-bff:").redis_key_prefix
