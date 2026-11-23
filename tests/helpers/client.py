from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

FRONTEND_ORIGIN = "https://admin.test.uz"
DEFAULT_CLIENT_IP = "10.20.30.40"


@asynccontextmanager
async def app_client(
    app: FastAPI, *, client_ip: str = DEFAULT_CLIENT_IP, origin: str | None = FRONTEND_ORIGIN
) -> AsyncIterator[httpx.AsyncClient]:
    """HTTP client bound to `app`, with the app's lifespan running.

    Like the real frontend, it sends `Origin` on every request (the CSRF Origin
    check rejects unsafe requests without it).
    """
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(client_ip, 50000))
    headers = {"Origin": origin} if origin else {}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="https://testserver", headers=headers
        ) as client,
    ):
        yield client


def extra_client(
    app: FastAPI, *, client_ip: str = DEFAULT_CLIENT_IP, origin: str | None = FRONTEND_ORIGIN
) -> httpx.AsyncClient:
    """A second browser for an app whose lifespan is already running (no lifespan)."""
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(client_ip, 50001))
    headers = {"Origin": origin} if origin else {}
    return httpx.AsyncClient(transport=transport, base_url="https://testserver", headers=headers)
