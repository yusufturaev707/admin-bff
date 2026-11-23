"""Section 6 / 12: timeouts, logout, own sessions, password change ends sessions."""

import httpx
from fastapi import FastAPI

from app.auth.dependencies import SESSION_COOKIE
from app.settings import Settings
from tests.auth_helpers import (
    AUTH,
    create_admin,
    login,
    random_password,
    start_login,
    totp_code,
    wrong_code,
)
from tests.conftest import FakeClock
from tests.helpers import extra_client


def csrf(token: str) -> dict[str, str]:
    return {"X-CSRF-Token": token}


async def test_idle_timeout_slides_with_activity(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    await login(client, await create_admin(settings, clock), clock)
    for _ in range(3):
        clock.advance(29 * 60)
        assert (await client.get(f"{AUTH}/session")).status_code == 200

    clock.advance(30 * 60)
    response = await client.get(f"{AUTH}/session")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "session_expired"
    assert f"{SESSION_COOKIE}=;" in response.headers["set-cookie"]


async def test_absolute_timeout_ends_an_active_session(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    await login(client, await create_admin(settings, clock), clock)
    elapsed = 0
    while elapsed < 12 * 3600 - 25 * 60:
        clock.advance(25 * 60)
        elapsed += 25 * 60
        assert (await client.get(f"{AUTH}/session")).status_code == 200

    clock.advance(25 * 60)
    assert (await client.get(f"{AUTH}/session")).status_code == 401


async def test_logout(client: httpx.AsyncClient, settings: Settings, clock: FakeClock) -> None:
    token = await login(client, await create_admin(settings, clock), clock)

    assert (await client.post(f"{AUTH}/logout")).status_code == 403  # no CSRF token
    response = await client.post(f"{AUTH}/logout", headers=csrf(token))
    assert response.status_code == 204
    assert f"{SESSION_COOKIE}=" in response.headers["set-cookie"]
    assert (await client.get(f"{AUTH}/session")).status_code == 401


async def test_list_and_revoke_own_sessions(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    other_admin = await create_admin(settings, clock)
    token = await login(client, admin, clock)
    async with extra_client(app) as second, extra_client(app) as stranger:
        await login(second, admin, clock)
        await login(stranger, other_admin, clock)

        listed = (await client.get(f"{AUTH}/sessions")).json()["items"]
        assert len(listed) == 2
        assert sorted(item["current"] for item in listed) == [False, True]
        other_id = next(item["id"] for item in listed if not item["current"])

        # Another admin's session id is "not found", never revocable.
        stranger_id = (await stranger.get(f"{AUTH}/session")).json()["id"]
        missing = await client.delete(f"{AUTH}/sessions/{stranger_id}", headers=csrf(token))
        assert missing.status_code == 404
        assert (await stranger.get(f"{AUTH}/session")).status_code == 200

        revoked = await client.delete(f"{AUTH}/sessions/{other_id}", headers=csrf(token))
        assert revoked.status_code == 204
        assert (await second.get(f"{AUTH}/session")).status_code == 401
        assert (await client.get(f"{AUTH}/session")).status_code == 200


async def test_password_change_ends_every_session(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    token = await login(client, admin, clock)
    async with extra_client(app) as second:
        await login(second, admin, clock)
        clock.advance(30)
        new_password = random_password()
        response = await client.post(
            f"{AUTH}/password",
            headers=csrf(token),
            json={
                "old_password": admin.password,
                "new_password": new_password,
                "code": totp_code(admin, clock),
            },
        )
        assert response.status_code == 204
        assert (await client.get(f"{AUTH}/session")).status_code == 401
        assert (await second.get(f"{AUTH}/session")).status_code == 401

    assert (await start_login(client, admin)).status_code == 401
    relogin = await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": new_password}
    )
    assert relogin.status_code == 200


async def test_password_change_checks(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock, username="operator")
    token = await login(client, admin, clock)

    async def change(old: str, new: str, code: str) -> httpx.Response:
        return await client.post(
            f"{AUTH}/password",
            headers=csrf(token),
            json={"old_password": old, "new_password": new, "code": code},
        )

    def error(response: httpx.Response) -> tuple[list[str], str]:
        field = response.json()["error"]["details"]["fields"][0]
        return field["loc"], field["type"]

    clock.advance(30)
    good_code = totp_code(admin, clock)
    strong = random_password()
    cases = [
        ((admin.password, "short", good_code), (["body", "new_password"], "password_too_short")),
        (
            (admin.password, "my-OPERATOR-pass-1", good_code),
            (["body", "new_password"], "password_contains_username"),
        ),
        (
            (admin.password, "Qwerty123456", good_code),
            (["body", "new_password"], "password_too_common"),
        ),
        ((random_password(), strong, good_code), (["body", "old_password"], "invalid_password")),
        ((admin.password, strong, wrong_code(good_code)), (["body", "code"], "invalid_code")),
    ]
    for (old, new, code), expected in cases:
        response = await change(old, new, code)
        assert response.status_code == 422, response.text
        assert error(response) == (expected[0], expected[1])

    reused = await change(admin.password, admin.password, good_code)
    assert reused.status_code == 422
    assert error(reused) == (["body", "new_password"], "password_reused")
