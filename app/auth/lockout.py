"""Login lockout with Redis counters (section 6).

* username: 5 failed attempts within 15 minutes -> blocked for 15 minutes;
* IP: 20 failed attempts within 10 minutes -> blocked for 30 minutes.

Counters are kept for any attempted username, existing or not, so a lockout
does not reveal whether an account exists. Wrong second-factor codes count as
failures of the same username.
"""

from dataclasses import dataclass

from redis.asyncio import Redis

from app.auth.crypto import sha256_hex


@dataclass(frozen=True, slots=True)
class LockRule:
    name: str
    max_failures: int
    window_s: int
    lock_s: int


USER_RULE = LockRule("user", max_failures=5, window_s=15 * 60, lock_s=15 * 60)
IP_RULE = LockRule("ip", max_failures=20, window_s=10 * 60, lock_s=30 * 60)

# Returns 1 if this failure created the lock.
_RECORD_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
if n >= tonumber(ARGV[2]) and redis.call('EXISTS', KEYS[2]) == 0 then
  redis.call('SET', KEYS[2], '1', 'EX', ARGV[3])
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
"""


class LoginLimiter:
    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix
        self._record = redis.register_script(_RECORD_LUA)

    def _keys(self, rule: LockRule, subject: str) -> tuple[str, str]:
        # Usernames are hashed so that Redis keys carry no account names.
        ident = sha256_hex(subject) if rule is USER_RULE else subject
        return (
            f"{self._prefix}login_fail:{rule.name}:{ident}",
            f"{self._prefix}login_lock:{rule.name}:{ident}",
        )

    def _subjects(self, username: str | None, ip: str) -> list[tuple[LockRule, str]]:
        subjects = [(IP_RULE, ip)]
        if username:
            subjects.append((USER_RULE, username))
        return subjects

    async def retry_after(self, username: str | None, ip: str) -> int | None:
        """Seconds until the longest active lock ends, or None if not locked."""
        ttls = [
            int(await self._redis.ttl(self._keys(rule, subject)[1]))
            for rule, subject in self._subjects(username, ip)
        ]
        longest = max(ttls)
        return longest if longest > 0 else None

    async def record_failure(self, username: str | None, ip: str) -> list[LockRule]:
        """Counts a failure; returns the rules whose lock was created just now."""
        created: list[LockRule] = []
        for rule, subject in self._subjects(username, ip):
            counter, lock = self._keys(rule, subject)
            locked_now = await self._record(
                keys=[counter, lock], args=[rule.window_s, rule.max_failures, rule.lock_s]
            )
            if int(locked_now) == 1:
                created.append(rule)
        return created

    async def reset_user(self, username: str) -> None:
        await self._redis.delete(self._keys(USER_RULE, username)[0])

    async def unlock(self, *, username: str | None = None, ip: str | None = None) -> int:
        """Lifts locks early (superadmin / CLI). Returns the number of keys removed."""
        keys: list[str] = []
        if username:
            keys += self._keys(USER_RULE, username)
        if ip:
            keys += self._keys(IP_RULE, ip)
        return int(await self._redis.delete(*keys)) if keys else 0
