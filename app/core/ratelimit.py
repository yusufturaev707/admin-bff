"""Fixed-window rate limits in Redis (section 11), e.g. 5 exports per hour.

    limiter = FixedWindowLimiter(redis, prefix=..., name="audit_export", limit=5, window_s=3600)
    if (retry_after := await limiter.check(subject)) is not None: ...  # before the work
    if (retry_after := await limiter.hit(subject)) is not None: ...    # counts one use

The window starts with the first use and lasts `window_s` seconds.
"""

from redis.asyncio import Redis

# Returns 0 if the use is allowed, otherwise the seconds until the window ends.
_HIT_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
if n > tonumber(ARGV[2]) then
  local ttl = redis.call('TTL', KEYS[1])
  if ttl < 1 then ttl = 1 end
  return ttl
end
return 0
"""


class FixedWindowLimiter:
    def __init__(self, redis: Redis, *, prefix: str, name: str, limit: int, window_s: int) -> None:
        self._redis = redis
        self._prefix = f"{prefix}ratelimit:{name}:"
        self.limit = limit
        self.window_s = window_s
        self._hit = redis.register_script(_HIT_LUA)

    async def check(self, subject: str) -> int | None:
        """Seconds to wait if the limit is already used up, otherwise None.
        Does not count a use."""
        key = self._prefix + subject
        used = await self._redis.get(key)
        if used is None or int(used) < self.limit:
            return None
        return max(int(await self._redis.ttl(key)), 1)

    async def hit(self, subject: str) -> int | None:
        """Counts one use. Seconds to wait if it is over the limit, otherwise None."""
        retry_after = int(
            await self._hit(keys=[self._prefix + subject], args=[self.window_s, self.limit])
        )
        return retry_after or None
