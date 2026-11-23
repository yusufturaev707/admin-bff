"""The session Redis client survives a pooled connection that died meanwhile."""

from app.core.redis import create_redis
from app.settings import Settings
from tests.conftest import Services


async def test_a_dead_pooled_connection_is_replaced(settings: Settings, services: Services) -> None:
    # A pooled connection can die while idle (a Redis restart, a NAT or proxy
    # dropping idle TCP). Here the server closes it, like those would. The
    # request using it must not fail with a 500.
    client = create_redis(settings)
    killer = services.redis()
    try:
        connection_id = await client.client_id()  # the one connection in the pool
        assert await killer.client_kill_filter(_id=str(connection_id)) == 1
        assert await client.get(f"{services.redis_prefix}missing") is None
        assert await client.client_id() != connection_id  # a new connection
    finally:
        await client.aclose()
        await killer.aclose()
