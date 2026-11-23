"""`AuthProvider`: the primary sign-in methods (architecture decision 4).

Each provider checks one primary method and returns the admin. The second
factor (TOTP or a recovery code) is the same for every provider. A future
OIDC provider is one more class here; sessions, CSRF and RBAC do not change.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.crypto import hmac_sha256_hex
from app.auth.models import AdminUser, AuthMethod, normalize_username
from app.auth.oneid import OneIdClient, OneIdError
from app.auth.passwords import PasswordService
from app.auth.second_factor import SecondFactor, SecondFactorVerifier


class AuthFailedError(Exception):
    """`reason` goes to the audit log only; the user always sees one message."""

    def __init__(self, reason: str, user: AdminUser | None = None) -> None:
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

    def __init__(self, second_factor: SecondFactorVerifier) -> None:
        self._second_factor = second_factor

    @abstractmethod
    async def authenticate(self, db: AsyncSession, credentials: CredentialsT) -> AdminUser:
        """Returns the active admin allowed to use this method, or raises AuthFailedError."""

    async def verify_second_factor(
        self, db: AsyncSession, user: AdminUser, factor: SecondFactor
    ) -> bool:
        return await self._second_factor.verify(db, user, factor)


class LocalAuthProvider(AuthProvider[PasswordCredentials]):
    method = AuthMethod.PASSWORD

    def __init__(self, second_factor: SecondFactorVerifier, passwords: PasswordService) -> None:
        super().__init__(second_factor)
        self._passwords = passwords

    async def authenticate(self, db: AsyncSession, credentials: PasswordCredentials) -> AdminUser:
        username = normalize_username(credentials.username)
        user = (
            await db.scalar(select(AdminUser).where(AdminUser.username == username))
            if username
            else None
        )
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

    def __init__(
        self, second_factor: SecondFactorVerifier, client: OneIdClient, pinfl_key: bytes
    ) -> None:
        super().__init__(second_factor)
        self._client = client
        self._pinfl_key = pinfl_key

    def pinfl_hash(self, pinfl: str) -> str:
        return hmac_sha256_hex(self._pinfl_key, pinfl)

    async def authenticate(self, db: AsyncSession, credentials: OneIdCredentials) -> AdminUser:
        try:
            identity = await self._client.exchange_code(credentials.code)
        except OneIdError as exc:
            raise AuthFailedError("oneid_error") from exc
        user = await db.scalar(
            select(AdminUser).where(AdminUser.oneid_pinfl_hash == self.pinfl_hash(identity.pinfl))
        )
        if user is None:
            raise AuthFailedError("unknown_pinfl")
        if not user.is_active:
            raise AuthFailedError("inactive", user)
        if not user.allows(self.method):
            raise AuthFailedError("method_not_allowed", user)
        return user
