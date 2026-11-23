"""Login lockout with Redis counters (section 6).

* username: 5 failed attempts within 15 minutes -> blocked for 15 minutes;
* IP: 20 failed attempts within 10 minutes -> blocked for 30 minutes.

Counters are kept for any attempted username, existing or not, so a lockout
does not reveal whether an account exists. A wrong current password on
`/auth/password` counts as a failure of that username.

An attempt is reserved before the credentials are checked (`acquire`) and
ended afterwards (`finish`). The reservation is atomic and counts attempts
still running together with failures, so parallel requests cannot all pass
the check first and then try more passwords than the limit allows.

Keys per rule and subject:

* `login_fail`: failures in the current window;
* `login_pending`: attempts still running. Its short TTL frees a reservation
  whose worker died before `finish`;
* `login_lock`: the lock itself.
"""

from dataclasses import dataclass
from typing import NamedTuple

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

# Longer than any attempt can take (an Argon2 check, or the OneID code exchange).
PENDING_TTL_S = 120
# Answer when the limit is taken up by attempts that are still running: they
# end within moments, then the caller sees either a free slot or the lock.
BUSY_RETRY_AFTER_S = 1

# KEYS: fail, lock, pending for each rule. ARGV: max_failures for each rule,
# then the pending TTL. Returns 0 if the attempt is reserved, the seconds until
# the longest lock ends, or -1 if failures and running attempts reach the limit.
_ACQUIRE_LUA = """
local rules = #KEYS / 3
local longest = 0
for i = 0, rules - 1 do
  local ttl = redis.call('TTL', KEYS[i * 3 + 2])
  if ttl > longest then longest = ttl end
end
if longest > 0 then return longest end
for i = 0, rules - 1 do
  local used = tonumber(redis.call('GET', KEYS[i * 3 + 1]) or '0')
    + tonumber(redis.call('GET', KEYS[i * 3 + 3]) or '0')
  if used >= tonumber(ARGV[i + 1]) then return -1 end
end
for i = 0, rules - 1 do
  redis.call('INCR', KEYS[i * 3 + 3])
  redis.call('EXPIRE', KEYS[i * 3 + 3], ARGV[rules + 1])
end
return 0
"""

# KEYS: fail, lock, pending for each rule. ARGV[1]: '1' if the attempt failed,
# then window, max_failures and lock seconds for each rule. Returns one flag per
# rule: 1 if this failure created the lock.
_FINISH_LUA = """
local rules = #KEYS / 3
local failed = ARGV[1] == '1'
local created = {}
for i = 0, rules - 1 do
  local fail, lock, pending = KEYS[i * 3 + 1], KEYS[i * 3 + 2], KEYS[i * 3 + 3]
  if tonumber(redis.call('GET', pending) or '0') > 0 then redis.call('DECR', pending) end
  created[i + 1] = 0
  if failed then
    local n = redis.call('INCR', fail)
    if n == 1 then redis.call('EXPIRE', fail, ARGV[i * 3 + 2]) end
    if n >= tonumber(ARGV[i * 3 + 3]) and redis.call('EXISTS', lock) == 0 then
      redis.call('SET', lock, '1', 'EX', ARGV[i * 3 + 4])
      redis.call('DEL', fail)
      created[i + 1] = 1
    end
  end
end
return created
"""


class _Keys(NamedTuple):
    fail: str
    lock: str
    pending: str


class LoginLimiter:
    def __init__(self, redis: Redis, *, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix
        self._acquire = redis.register_script(_ACQUIRE_LUA)
        self._finish = redis.register_script(_FINISH_LUA)

    def _keys(self, rule: LockRule, subject: str) -> _Keys:
        # Usernames are hashed so that Redis keys carry no account names.
        ident = sha256_hex(subject) if rule is USER_RULE else subject
        return _Keys(
            f"{self._prefix}login_fail:{rule.name}:{ident}",
            f"{self._prefix}login_lock:{rule.name}:{ident}",
            f"{self._prefix}login_pending:{rule.name}:{ident}",
        )

    def _subjects(self, username: str | None, ip: str) -> tuple[list[LockRule], list[str]]:
        """The rules that apply and their keys, three per rule."""
        subjects = [(IP_RULE, ip)]
        if username:
            subjects.append((USER_RULE, username))
        rules = [rule for rule, _ in subjects]
        keys = [key for rule, subject in subjects for key in self._keys(rule, subject)]
        return rules, keys

    async def acquire(self, username: str | None, ip: str) -> int | None:
        """Reserves one attempt before the credentials are checked. Returns None
        if it may go ahead, otherwise the seconds to wait. Every reservation
        must be ended with `finish`, whatever happens in between."""
        rules, keys = self._subjects(username, ip)
        result = int(
            await self._acquire(
                keys=keys, args=[*(rule.max_failures for rule in rules), PENDING_TTL_S]
            )
        )
        if result == 0:
            return None
        return result if result > 0 else BUSY_RETRY_AFTER_S

    async def finish(self, username: str | None, ip: str, *, failed: bool) -> list[LockRule]:
        """Ends an attempt reserved by `acquire`; a failed one is counted.
        Returns the rules whose lock this failure created."""
        rules, keys = self._subjects(username, ip)
        args: list[int | str] = ["1" if failed else "0"]
        for rule in rules:
            args += [rule.window_s, rule.max_failures, rule.lock_s]
        flags = await self._finish(keys=keys, args=args)
        return [rule for rule, flag in zip(rules, flags, strict=True) if int(flag) == 1]

    async def reset_user(self, username: str) -> None:
        await self._redis.delete(self._keys(USER_RULE, username).fail)

    async def unlock(self, *, username: str | None = None, ip: str | None = None) -> int:
        """Lifts locks early (superadmin). Returns the number of keys removed."""
        keys: list[str] = []
        if username:
            user = self._keys(USER_RULE, username)
            keys += [user.fail, user.lock]
        if ip:
            address = self._keys(IP_RULE, ip)
            keys += [address.fail, address.lock]
        return int(await self._redis.delete(*keys)) if keys else 0
