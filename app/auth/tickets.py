"""Short-lived one-time values in Redis: mfa tokens, OAuth state, pending TOTP secrets."""

import re
import uuid
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from app.auth.crypto import new_token, sha256_hex
from app.auth.models import AuthMethod

MFA_TOKEN_TTL_S = 5 * 60
MFA_MAX_ATTEMPTS = 5

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

# Counts a wrong code; the token is destroyed after MFA_MAX_ATTEMPTS.
_FAIL_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
local n = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if n >= tonumber(ARGV[1]) then redis.call('DEL', KEYS[1]) end
return n
"""


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    return value if isinstance(value, bytes) else str(value).encode()


@dataclass(frozen=True, slots=True)
class MfaTicket:
    user_id: uuid.UUID
    username: str
    method: AuthMethod


class MfaTokenStore:
    """`mfa_token` from /auth/login: one-time, 5 minutes, at most 5 wrong codes."""

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix
        self._fail = redis.register_script(_FAIL_LUA)

    def _key(self, token: str) -> str:
        return f"{self._prefix}mfa:{sha256_hex(token)}"

    async def issue(self, *, user_id: uuid.UUID, username: str, method: AuthMethod) -> str:
        token = new_token()
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(
                self._key(token),
                mapping={
                    "user_id": str(user_id),
                    "username": username,
                    "method": method.value,
                    "attempts": "0",
                },
            )
            pipe.expire(self._key(token), MFA_TOKEN_TTL_S)
            await pipe.execute()
        return token

    async def get(self, token: str) -> MfaTicket | None:
        if not _TOKEN_RE.fullmatch(token):
            return None
        raw = await self._redis.hgetall(self._key(token))
        if not raw:
            return None
        fields = {_text(k): _text(v) for k, v in raw.items()}
        try:
            return MfaTicket(
                user_id=uuid.UUID(fields["user_id"]),
                username=fields["username"],
                method=AuthMethod(fields["method"]),
            )
        except (KeyError, ValueError):
            return None

    async def record_failure(self, token: str) -> int:
        return int(await self._fail(keys=[self._key(token)], args=[MFA_MAX_ATTEMPTS]))

    async def consume(self, token: str) -> bool:
        """True only for the first caller: the token cannot be used twice."""
        return int(await self._redis.delete(self._key(token))) == 1


class OneTimeStore:
    """Small values with a TTL, read once (`take`) or explicitly deleted."""

    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, namespace: str, name: str) -> str:
        return f"{self._prefix}{namespace}:{name}"

    async def put(self, namespace: str, name: str, value: bytes, *, ttl_s: int) -> None:
        await self._redis.set(self._key(namespace, name), value, ex=ttl_s)

    async def get(self, namespace: str, name: str) -> bytes | None:
        return _bytes(await self._redis.get(self._key(namespace, name)))

    async def take(self, namespace: str, name: str) -> bytes | None:
        return _bytes(await self._redis.getdel(self._key(namespace, name)))

    async def delete(self, namespace: str, name: str) -> None:
        await self._redis.delete(self._key(namespace, name))
