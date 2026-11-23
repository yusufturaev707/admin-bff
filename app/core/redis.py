"""Session/cache Redis (redis-py asyncio).

This is the BFF's private Redis (sessions, cache, rate limits). The events Redis
that other systems write to is a separate instance (section 10.1) and is never
configured here.
"""

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import ConstantBackoff
from redis.exceptions import ConnectionError as RedisConnectionError

from app.settings import Settings

# A pooled connection can die while idle: a Redis restart, or a NAT or proxy
# that drops idle TCP (WSL2's localhost relay does it after about a minute).
# Without a retry the request that picks it up fails with a 500. One retry on a
# fresh connection hides that. Only connection errors are retried, never
# timeouts: a command that timed out may already have run, and the lockout and
# rate-limit scripts must not count twice.
_RETRY = Retry(ConstantBackoff(0.05), retries=1, supported_errors=(RedisConnectionError,))


def create_redis(settings: Settings) -> Redis:
    return Redis.from_url(
        settings.redis_url,
        password=settings.redis_password.get_secret_value() if settings.redis_password else None,
        socket_timeout=2,
        socket_connect_timeout=2,
        health_check_interval=30,
        retry=_RETRY,
    )


async def ping_redis(client: Redis) -> None:
    await client.ping()
