"""Session/cache Redis (redis-py asyncio).

This is the BFF's private Redis (sessions, cache, rate limits). The events Redis
that other systems write to is a separate instance (section 10.1) and is never
configured here.
"""

from redis.asyncio import Redis

from app.settings import Settings


def create_redis(settings: Settings) -> Redis:
    return Redis.from_url(
        settings.redis_url,
        password=settings.redis_password.get_secret_value() if settings.redis_password else None,
        socket_timeout=2,
        socket_connect_timeout=2,
        health_check_interval=30,
    )


async def ping_redis(client: Redis) -> None:
    await client.ping()
