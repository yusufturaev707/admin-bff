"""Password hashing (Argon2id) and password policy (section 6)."""

import asyncio
import secrets
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

from app.settings import Settings

MIN_LENGTH = 12
MAX_LENGTH = 256  # bounds hashing work per request

COMMON_PASSWORDS_FILE = Path(__file__).parent / "data" / "common_passwords.txt"


class PasswordPolicyError(Exception):
    """`reason` is a stable code for the frontend, `message` is Uzbek text."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.message = message


@lru_cache(maxsize=1)
def load_common_passwords(path: Path = COMMON_PASSWORDS_FILE) -> frozenset[str]:
    with path.open(encoding="utf-8") as fh:
        return frozenset(
            line.strip().lower() for line in fh if line.strip() and not line.startswith("#")
        )


def check_password_policy(password: str, *, username: str) -> None:
    """Length, username and common-password rules. No forced periodic change."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(
            "password_too_short", f"Parol kamida {MIN_LENGTH} ta belgidan iborat bo'lishi kerak"
        )
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(
            "password_too_long", f"Parol {MAX_LENGTH} ta belgidan oshmasligi kerak"
        )
    if username and username.lower() in password.lower():
        raise PasswordPolicyError(
            "password_contains_username", "Parolda foydalanuvchi nomi bo'lmasligi kerak"
        )
    if password.lower() in load_common_passwords():
        raise PasswordPolicyError(
            "password_too_common", "Bu parol juda keng tarqalgan, boshqasini tanlang"
        )


class PasswordService:
    """Argon2id hashing. Hashing runs in a worker thread: it is CPU and memory
    heavy by design and must not block the event loop."""

    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            type=Type.ID,
        )
        # Verified when the user does not exist, so a missing account takes as
        # long as a wrong password (no user enumeration through timing).
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(24))

    async def hash(self, password: str) -> str:
        return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, password_hash: str | None, password: str) -> bool:
        """Constant-ish time: always performs one Argon2 verification."""
        target = password_hash if password_hash is not None else self._dummy_hash
        try:
            await asyncio.to_thread(self._hasher.verify, target, password)
        except (VerificationError, InvalidHashError):
            return False
        return password_hash is not None

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)
