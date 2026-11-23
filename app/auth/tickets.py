"""Short-lived one-time values in Redis (the OneID state)."""

from typing import Any

from redis.asyncio import Redis


def _bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    return value if isinstance(value, bytes) else str(value).encode()


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
