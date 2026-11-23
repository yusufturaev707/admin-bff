"""Unit tests: crypto, password policy, TOTP, recovery codes, auth settings."""

import base64
import secrets
import uuid
from datetime import timedelta

import pyotp
import pytest
from pydantic import SecretStr, ValidationError

from app.auth import totp
from app.auth.crypto import DecryptionError, SecretBox
from app.auth.models import normalize_username
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.core.time import utcnow
from app.settings import Settings
from tests.conftest import random_key


def test_secret_box_roundtrip_and_binding() -> None:
    box = SecretBox(secrets.token_bytes(32))
    owner, other = uuid.uuid4().bytes, uuid.uuid4().bytes
    blob = box.encrypt(b"JBSWY3DPEHPK3PXP", aad=owner)
    assert box.decrypt(blob, aad=owner) == b"JBSWY3DPEHPK3PXP"
    assert blob != box.encrypt(b"JBSWY3DPEHPK3PXP", aad=owner)  # random nonce
    with pytest.raises(DecryptionError):
        box.decrypt(blob, aad=other)  # copied to another admin
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(DecryptionError):
        box.decrypt(tampered, aad=owner)
    with pytest.raises(DecryptionError):
        SecretBox(secrets.token_bytes(32)).decrypt(blob, aad=owner)  # wrong key


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


def test_totp_accepts_one_step_of_drift_only() -> None:
    secret = totp.new_secret()
    now = utcnow()
    generator = pyotp.TOTP(secret)
    current = generator.timecode(now)
    assert totp.match_timecode(secret, generator.at(now), now) == current
    assert (
        totp.match_timecode(secret, generator.at(now - timedelta(seconds=30)), now) == current - 1
    )
    assert (
        totp.match_timecode(secret, generator.at(now + timedelta(seconds=30)), now) == current + 1
    )
    assert totp.match_timecode(secret, generator.at(now - timedelta(seconds=60)), now) is None
    for malformed in ("12345", "1234567", "12a456", "١٢٣٤٥٦"):
        assert totp.match_timecode(secret, malformed, now) is None


def test_recovery_codes() -> None:
    code = totp.new_recovery_code()
    assert len(code) == 19
    assert code.count("-") == 3
    assert totp.normalize_recovery_code(code.lower().replace("-", " ")) == code.replace("-", "")
    assert totp.normalize_recovery_code("O0O0-I1I1-O0O0-I1I1") is None  # ambiguous symbols
    assert totp.normalize_recovery_code("ABCD") is None
    assert len({totp.new_recovery_code() for _ in range(50)}) == 50


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
            Settings(_env_file=None, app_env="test", totp_enc_key=SecretStr(bad))
        with pytest.raises(ValidationError):
            Settings(_env_file=None, app_env="test", pinfl_hmac_key=SecretStr(bad))
    settings = Settings(_env_file=None, app_env="test", totp_enc_key=random_key())
    assert len(settings.totp_key()) == 32
    with pytest.raises(RuntimeError, match="PINFL_HMAC_KEY"):
        settings.pinfl_key()


def test_production_refuses_weak_argon2(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="Argon2id"):
        Settings(_env_file=None, argon2_memory_cost_kib=1024)
    assert Settings(_env_file=None).argon2_memory_cost_kib == 64 * 1024


def test_redis_key_prefix_is_validated(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, redis_key_prefix="bad prefix*")
    assert Settings(_env_file=None, redis_key_prefix="dev:admin-bff:").redis_key_prefix


def test_secret_box_key_rotation() -> None:
    old, new = secrets.token_bytes(32), secrets.token_bytes(32)
    owner = uuid.uuid4().bytes
    old_blob = SecretBox(old).encrypt(b"JBSWY3DPEHPK3PXP", aad=owner)

    ring = SecretBox(new, previous=[old])
    assert ring.decrypt(old_blob, aad=owner) == b"JBSWY3DPEHPK3PXP"
    assert not ring.is_current(old_blob)
    new_blob = ring.encrypt(b"JBSWY3DPEHPK3PXP", aad=owner)
    assert ring.is_current(new_blob)

    # After the rotation the old key is removed: only re-encrypted blobs open.
    assert SecretBox(new).decrypt(new_blob, aad=owner) == b"JBSWY3DPEHPK3PXP"
    with pytest.raises(DecryptionError, match="not configured"):
        SecretBox(new).decrypt(old_blob, aad=owner)
