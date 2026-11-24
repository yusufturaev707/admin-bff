from typing import Any

import httpx


class Browser:
    """One signed-in admin: a client plus its CSRF token (fixture `browsers`)."""

    def __init__(self, client: httpx.AsyncClient, csrf: str) -> None:
        self.client = client
        self.headers = {"X-CSRF-Token": csrf}

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.client.get(path, **kwargs)

    async def send(self, method: str, path: str, json: Any = None) -> httpx.Response:
        return await self.client.request(method, path, json=json, headers=self.headers)
