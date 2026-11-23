"""Section 6 / 12: CSRF token and Origin checks."""

import httpx
import pytest
from fastapi import FastAPI

from app.settings import Settings
from tests.conftest import FakeClock
from tests.helpers.auth import AUTH, create_admin, login
from tests.helpers.client import extra_client


async def test_post_without_csrf_token_is_rejected(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    await login(client, await create_admin(settings, clock), clock)
    response = await client.post(f"{AUTH}/logout")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_post_with_wrong_csrf_token_is_rejected(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    token = await login(client, await create_admin(settings, clock), clock)
    altered = token[:-1] + ("A" if token[-1] != "A" else "B")
    # Raw bytes: a non-ASCII header value must be rejected, not crash the check.
    for bad in (altered.encode(), b"", "ü".encode("latin-1") * 10):
        response = await client.post(f"{AUTH}/logout", headers={b"X-CSRF-Token": bad})
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "csrf_failed"
    assert (await client.get(f"{AUTH}/session")).status_code == 200  # still signed in


@pytest.mark.parametrize("origin", ["https://evil.test", "http://admin.test.uz", None])
async def test_wrong_or_missing_origin_is_rejected(
    app: FastAPI,
    client: httpx.AsyncClient,
    settings: Settings,
    clock: FakeClock,
    origin: str | None,
) -> None:
    admin = await create_admin(settings, clock)
    token = await login(client, admin, clock)
    async with extra_client(app, origin=origin) as other:
        other.cookies = client.cookies
        # Even with a valid session cookie and CSRF token.
        logout = await other.post(f"{AUTH}/logout", headers={"X-CSRF-Token": token})
        assert logout.status_code == 403
        assert logout.json()["error"]["code"] == "csrf_failed"
        # Login itself is protected too (login CSRF).
        sign_in = await other.post(
            f"{AUTH}/login", json={"username": admin.username, "password": admin.password}
        )
        assert sign_in.status_code == 403
        # Safe methods are not affected.
        assert (await other.get(f"{AUTH}/session")).status_code == 200
