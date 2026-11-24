"""`AuthProvider`: the primary sign-in methods (architecture decision 4).

Each provider checks one sign-in method and returns the admin. A future OIDC
provider is one more class here; sessions, CSRF and RBAC do not change.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.crypto import hmac_sha256_hex
from app.auth.models import AuthMethod, User, normalize_username
from app.auth.oneid import OneIdClient, OneIdError
from app.auth.passwords import PasswordService


class AuthFailedError(Exception):
    """`reason` goes to the audit log only; the user always sees one message."""

    def __init__(self, reason: str, user: User | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user = user


@dataclass(frozen=True, slots=True)
class PasswordCredentials:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class OneIdCredentials:
    code: str


class AuthProvider[CredentialsT](ABC):
    method: ClassVar[AuthMethod]

    @abstractmethod
    async def authenticate(self, db: AsyncSession, credentials: CredentialsT) -> User:
        """Returns the active admin allowed to use this method, or raises AuthFailedError."""


class LocalAuthProvider(AuthProvider[PasswordCredentials]):
    method = AuthMethod.PASSWORD

    def __init__(self, passwords: PasswordService) -> None:
        self._passwords = passwords

    async def authenticate(self, db: AsyncSession, credentials: PasswordCredentials) -> User:
        username = normalize_username(credentials.username)
        user = await db.scalar(select(User).where(User.username == username)) if username else None
        # Always one Argon2 verification (a dummy hash for unknown users), so the
        # response time does not tell whether the account exists.
        password_ok = await self._passwords.verify(
            user.password_hash if user else None, credentials.password
        )
        if user is None:
            raise AuthFailedError("unknown_user")
        if not password_ok:
            raise AuthFailedError("bad_password", user)
        if not user.is_active:
            raise AuthFailedError("inactive", user)
        if not user.allows(self.method):
            raise AuthFailedError("method_not_allowed", user)
        if user.password_hash and self._passwords.needs_rehash(user.password_hash):
            user.password_hash = await self._passwords.hash(credentials.password)
        return user


class OneIdAuthProvider(AuthProvider[OneIdCredentials]):
    """OneID proves who the citizen is; it does not make anyone an admin. Only
    an existing, active admin whose PINFL the superadmin linked may sign in."""

    method = AuthMethod.ONEID

    def __init__(self, client: OneIdClient, pinfl_key: bytes) -> None:
        self._client = client
        self._pinfl_key = pinfl_key

    def imie_hash(self, imie: str) -> str:
        return hmac_sha256_hex(self._pinfl_key, imie)

    async def authenticate(self, db: AsyncSession, credentials: OneIdCredentials) -> User:
        try:
            identity = await self._client.exchange_code(credentials.code)
        except OneIdError as exc:
            raise AuthFailedError("oneid_error") from exc
        user = await db.scalar(
            select(User).where(User.oneid_imie_hash == self.imie_hash(identity.pinfl))
        )
        if user is None:
            raise AuthFailedError("unknown_imie")
        if not user.is_active:
            raise AuthFailedError("inactive", user)
        if not user.allows(self.method):
            raise AuthFailedError("method_not_allowed", user)
        return user
