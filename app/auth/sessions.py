"""Server-side sessions in Redis (section 6).

* The browser holds only a random session id in an HttpOnly cookie. Redis keys
  use its SHA-256 (`sess:<sha256(id)>`), the id itself is never stored.
* Idle timeout (sliding) and absolute timeout are checked in code against the
  injected clock; the Redis TTL is only a backstop that frees memory.
* `user_sessions:<user_id>` indexes a user's sessions so they can all be
  revoked at once (password change, block, role change).
"""

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, cast

from redis.asyncio import Redis
from redis.typing import EncodableT, FieldT

from app.auth.crypto import new_token, sha256_hex
from app.auth.models import AuthMethod
from app.core.time import Clock

_RAW_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_USER_AGENT_MAX = 256

# Updates fields only if the session still exists (never resurrects an expired
# session as a partial hash without TTL), then refreshes the TTL.
_TOUCH_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if #ARGV > 1 then redis.call('HSET', KEYS[1], unpack(ARGV, 2)) end
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
"""


class PendingStep(StrEnum):
    """Setup steps that must be finished before the session gets full access."""

    TOTP_ENROLLMENT = "totp_enrollment"
    PASSWORD_CHANGE = "password_change"  # noqa: S105 - a step name, not a secret  # nosec B105


@dataclass(frozen=True, slots=True)
class SessionData:
    key: str  # sha256 of the session id; also the public id in /auth/sessions
    user_id: uuid.UUID
    username: str
    auth_method: AuthMethod
    created_at: datetime
    last_seen: datetime
    mfa_at: datetime | None
    ip: str
    user_agent: str
    csrf_token: str
    perm_version: int
    pending: tuple[PendingStep, ...]

    @property
    def setup_required(self) -> bool:
        return bool(self.pending)

    def to_redis(self) -> dict[str, str]:
        return {
            "user_id": str(self.user_id),
            "username": self.username,
            "auth_method": self.auth_method.value,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mfa_at": self.mfa_at.isoformat() if self.mfa_at else "",
            "ip": self.ip,
            "user_agent": self.user_agent,
            "csrf_token": self.csrf_token,
            "perm_version": str(self.perm_version),
            "pending": ",".join(step.value for step in self.pending),
        }

    @classmethod
    def from_redis(cls, key: str, raw: Mapping[Any, Any]) -> "SessionData | None":
        """None for a missing or malformed hash (treated as no session)."""
        fields = {
            (k.decode() if isinstance(k, bytes) else str(k)): (
                v.decode() if isinstance(v, bytes) else str(v)
            )
            for k, v in raw.items()
        }
        try:
            return cls(
                key=key,
                user_id=uuid.UUID(fields["user_id"]),
                username=fields["username"],
                auth_method=AuthMethod(fields["auth_method"]),
                created_at=datetime.fromisoformat(fields["created_at"]),
                last_seen=datetime.fromisoformat(fields["last_seen"]),
                mfa_at=datetime.fromisoformat(fields["mfa_at"]) if fields["mfa_at"] else None,
                ip=fields["ip"],
                user_agent=fields["user_agent"],
                csrf_token=fields["csrf_token"],
                perm_version=int(fields["perm_version"]),
                pending=tuple(PendingStep(p) for p in fields["pending"].split(",") if p),
            )
        except (KeyError, ValueError):
            return None


class SessionStore:
    def __init__(
        self,
        redis: Redis,
        *,
        prefix: str,
        idle_timeout_s: int,
        absolute_timeout_s: int,
        clock: Clock,
    ) -> None:
        self._redis = redis
        self._prefix = prefix
        self._idle = timedelta(seconds=idle_timeout_s)
        self._absolute = timedelta(seconds=absolute_timeout_s)
        self._clock = clock
        self._touch = redis.register_script(_TOUCH_LUA)

    def _key(self, session_key: str) -> str:
        return f"{self._prefix}sess:{session_key}"

    def _index(self, user_id: uuid.UUID) -> str:
        return f"{self._prefix}user_sessions:{user_id}"

    def _ttl(self, data: SessionData, now: datetime) -> int:
        remaining = min(self._idle, data.created_at + self._absolute - now)
        return max(1, int(remaining.total_seconds()))

    def _expired(self, data: SessionData, now: datetime) -> bool:
        return now - data.last_seen >= self._idle or now - data.created_at >= self._absolute

    def expires_at(self, data: SessionData) -> datetime:
        """When the session ends at the latest (idle or absolute, whichever first)."""
        return min(data.last_seen + self._idle, data.created_at + self._absolute)

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        username: str,
        auth_method: AuthMethod,
        ip: str,
        user_agent: str,
        mfa_at: datetime | None,
        pending: Sequence[PendingStep],
        perm_version: int,
        created_at: datetime | None = None,
    ) -> tuple[str, SessionData]:
        """Always a brand-new id (session fixation protection). Returns (id, data)."""
        session_id = new_token()
        now = self._clock()
        data = SessionData(
            key=sha256_hex(session_id),
            user_id=user_id,
            username=username,
            auth_method=auth_method,
            created_at=created_at or now,
            last_seen=now,
            mfa_at=mfa_at,
            ip=ip,
            user_agent=user_agent[:_USER_AGENT_MAX],
            csrf_token=new_token(),
            perm_version=perm_version,
            pending=tuple(pending),
        )
        async with self._redis.pipeline(transaction=True) as pipe:
            # redis-py's Mapping type is invariant in its key type; the values are plain str.
            fields = cast("Mapping[FieldT, EncodableT]", data.to_redis())
            pipe.hset(self._key(data.key), mapping=fields)
            pipe.expire(self._key(data.key), self._ttl(data, now))
            pipe.sadd(self._index(user_id), data.key)
            pipe.expire(self._index(user_id), int(self._absolute.total_seconds()))
            await pipe.execute()
        return session_id, data

    async def _read(self, session_key: str) -> SessionData | None:
        raw = await self._redis.hgetall(self._key(session_key))
        return SessionData.from_redis(session_key, raw) if raw else None

    async def load(self, session_id: str) -> SessionData | None:
        """Resolves a cookie value; slides the idle timeout. None if invalid/expired."""
        if not _RAW_ID_RE.fullmatch(session_id):
            return None
        data = await self._read(sha256_hex(session_id))
        if data is None:
            return None
        now = self._clock()
        if self._expired(data, now):
            await self.delete(data)
            return None
        return await self.update(data, last_seen=now)

    async def update(self, data: SessionData, **changes: Any) -> SessionData | None:
        """Writes the changed fields if the session still exists."""
        updated = replace(data, **changes)
        new_fields = updated.to_redis()
        old_fields = data.to_redis()
        args: list[str] = [str(self._ttl(updated, self._clock()))]
        for name, value in new_fields.items():
            if old_fields[name] != value:
                args += [name, value]
        ok = await self._touch(keys=[self._key(data.key)], args=args)
        return updated if int(ok) == 1 else None

    async def rotate(self, data: SessionData, **changes: Any) -> tuple[str, SessionData]:
        """New id for the same login (after a privilege change), old id is deleted.
        The absolute timeout keeps counting from the original login."""
        merged = replace(data, **changes)
        session_id, new = await self.create(
            user_id=merged.user_id,
            username=merged.username,
            auth_method=merged.auth_method,
            ip=merged.ip,
            user_agent=merged.user_agent,
            mfa_at=merged.mfa_at,
            pending=merged.pending,
            perm_version=merged.perm_version,
            created_at=data.created_at,
        )
        await self.delete(data)
        return session_id, new

    async def delete(self, data: SessionData) -> None:
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(self._key(data.key))
            pipe.srem(self._index(data.user_id), data.key)
            await pipe.execute()

    async def list_for_user(self, user_id: uuid.UUID) -> list[SessionData]:
        keys = sorted(
            (k.decode() if isinstance(k, bytes) else str(k))
            for k in await self._redis.smembers(self._index(user_id))
        )
        now = self._clock()
        alive: list[SessionData] = []
        stale: list[str] = []
        for key in keys:
            data = await self._read(key)
            if data is None or self._expired(data, now):
                stale.append(key)
            else:
                alive.append(data)
        if stale:
            await self._redis.srem(self._index(user_id), *stale)
        return sorted(alive, key=lambda s: s.created_at)

    async def delete_all_for_user(self, user_id: uuid.UUID) -> int:
        keys = [
            (k.decode() if isinstance(k, bytes) else str(k))
            for k in await self._redis.smembers(self._index(user_id))
        ]
        async with self._redis.pipeline(transaction=True) as pipe:
            for key in keys:
                pipe.delete(self._key(key))
            pipe.delete(self._index(user_id))
            await pipe.execute()
        return len(keys)
