"""Second factor: TOTP codes and one-time recovery codes.

The same second factor is required after every primary method (password and
OneID), so it lives outside the providers.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import totp
from app.auth.crypto import SecretBox
from app.auth.models import AdminUser, RecoveryCode
from app.auth.passwords import PasswordService
from app.core.time import Clock


@dataclass(frozen=True, slots=True)
class TotpFactor:
    code: str


@dataclass(frozen=True, slots=True)
class RecoveryFactor:
    code: str


type SecondFactor = TotpFactor | RecoveryFactor


class SecondFactorVerifier:
    def __init__(self, *, box: SecretBox, passwords: PasswordService, clock: Clock) -> None:
        self._box = box
        self._passwords = passwords
        self._clock = clock

    def encrypt_secret(self, user_id: uuid.UUID, secret: str) -> bytes:
        return self._box.encrypt(secret.encode(), aad=user_id.bytes)

    def decrypt_secret(self, user_id: uuid.UUID, blob: bytes) -> str:
        return self._box.decrypt(blob, aad=user_id.bytes).decode()

    async def verify(self, db: AsyncSession, user: AdminUser, factor: SecondFactor) -> bool:
        if isinstance(factor, TotpFactor):
            return await self._verify_totp(db, user, factor.code)
        return await self._verify_recovery(db, user, factor.code)

    async def _verify_totp(self, db: AsyncSession, user: AdminUser, code: str) -> bool:
        if not user.totp_enabled or user.totp_secret_enc is None:
            return False
        secret = self.decrypt_secret(user.id, user.totp_secret_enc)
        step = totp.match_timecode(secret, code, self._clock())
        if step is None:
            return False
        # Atomic replay protection: only a newer time step than the last
        # accepted one is stored, so two requests can never use one code.
        accepted = await db.scalar(
            update(AdminUser)
            .where(
                AdminUser.id == user.id,
                or_(AdminUser.totp_last_timecode.is_(None), AdminUser.totp_last_timecode < step),
            )
            .values(totp_last_timecode=step)
            .returning(AdminUser.id)
        )
        return accepted is not None

    async def _verify_recovery(self, db: AsyncSession, user: AdminUser, code: str) -> bool:
        normalized = totp.normalize_recovery_code(code)
        if normalized is None:
            return False
        rows = await db.scalars(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
            )
        )
        for row in rows.all():
            if await self._passwords.verify(row.code_hash, normalized):
                used = await db.scalar(
                    update(RecoveryCode)
                    .where(RecoveryCode.id == row.id, RecoveryCode.used_at.is_(None))
                    .values(used_at=self._clock())
                    .returning(RecoveryCode.id)
                )
                return used is not None
        return False

    async def replace_recovery_codes(self, db: AsyncSession, user_id: uuid.UUID) -> list[str]:
        """Deletes the old codes and returns 10 new ones (shown to the admin once)."""
        await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
        codes = [totp.new_recovery_code() for _ in range(totp.RECOVERY_CODE_COUNT)]
        for code in codes:
            normalized = totp.normalize_recovery_code(code)
            if normalized is None:  # pragma: no cover - generated codes are always valid
                raise RuntimeError("generated an invalid recovery code")
            db.add(RecoveryCode(user_id=user_id, code_hash=await self._passwords.hash(normalized)))
        return codes

    async def remaining_recovery_codes(self, db: AsyncSession, user_id: uuid.UUID) -> int:
        count = await db.scalar(
            select(func.count())
            .select_from(RecoveryCode)
            .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        )
        return int(count or 0)
