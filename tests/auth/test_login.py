"""Section 6 / 12: login, lockout, session fixation."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI

from app.audit.sink import AuditOutcome
from app.auth.crypto import sha256_hex
from app.auth.dependencies import SESSION_COOKIE
from app.main import create_app
from app.settings import Settings
from tests.conftest import AuditRecorder, FakeClock, Services
from tests.helpers.auth import AUTH, create_admin, random_password, start_login
from tests.helpers.client import app_client, extra_client


def _body_without_request_id(response: httpx.Response) -> dict[str, object]:
    error = dict(response.json()["error"])
    error.pop("request_id")
    return error


async def test_login_with_password(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    admin = await create_admin(settings, clock)

    second = await start_login(client, admin)
    assert second.status_code == 200
    assert second.headers["cache-control"] == "no-store"
    assert second.json()["setup_required"] is False
    assert second.json()["pending"] == []
    cookie = second.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attribute in cookie
    assert "Domain" not in cookie

    session = await client.get(f"{AUTH}/session")
    assert session.status_code == 200
    assert session.json()["username"] == admin.username
    assert session.json()["auth_method"] == "password"
    assert session.json()["csrf_token"] == second.json()["csrf_token"]
    assert session.json()["created_at"].endswith("Z")
    assert audit.find("auth.login", AuditOutcome.SUCCESS)


async def test_wrong_password_and_unknown_user_get_the_same_answer(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    admin = await create_admin(settings, clock)

    wrong_password = await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": random_password()}
    )
    unknown_user = await client.post(
        f"{AUTH}/login", json={"username": "no_such_admin", "password": random_password()}
    )
    invalid_name = await client.post(
        f"{AUTH}/login", json={"username": "!", "password": random_password()}
    )

    assert wrong_password.status_code == unknown_user.status_code == invalid_name.status_code == 401
    body = _body_without_request_id(wrong_password)
    assert body == _body_without_request_id(unknown_user) == _body_without_request_id(invalid_name)
    assert body["message"] == "Login yoki parol noto'g'ri"
    reasons = {e.details["reason"] for e in audit.find("auth.login", AuditOutcome.DENIED)}
    assert reasons == {"bad_password", "unknown_user"}


async def test_username_is_case_insensitive(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    response = await client.post(
        f"{AUTH}/login",
        json={"username": f"  {admin.username.upper()} ", "password": admin.password},
    )
    assert response.status_code == 200


async def test_inactive_or_oneid_only_admin_cannot_use_the_password(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    inactive = await create_admin(settings, clock, active=False)
    oneid_only = await create_admin(settings, clock, methods=("oneid",))
    for admin in (inactive, oneid_only):
        response = await start_login(client, admin)
        assert response.status_code == 401
        assert response.json()["error"]["message"] == "Login yoki parol noto'g'ri"


async def test_username_is_locked_after_five_failures(
    app: FastAPI,
    client: httpx.AsyncClient,
    settings: Settings,
    clock: FakeClock,
    audit: AuditRecorder,
) -> None:
    admin = await create_admin(settings, clock)
    for _ in range(5):
        response = await client.post(
            f"{AUTH}/login", json={"username": admin.username, "password": random_password()}
        )
        assert response.status_code == 401

    # Even the correct password is refused while the lock lasts.
    locked = await start_login(client, admin)
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "rate_limited"
    assert 0 < int(locked.headers["retry-after"]) <= 15 * 60
    lockouts = audit.find("auth.lockout")
    assert [e.details["rule"] for e in lockouts] == ["user"]

    # The superadmin (here: the limiter, as the admin API does) can lift it early.
    await app.state.auth_service.limiter.unlock(username=admin.username)
    assert (await start_login(client, admin)).status_code == 200


async def test_parallel_guesses_cannot_exceed_the_limit(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    # The attempt is reserved before the password is checked, so requests sent
    # at once cannot all pass the lock check first and then guess.
    admin = await create_admin(settings, clock)
    responses = await asyncio.gather(
        *(
            client.post(
                f"{AUTH}/login", json={"username": admin.username, "password": random_password()}
            )
            for _ in range(12)
        )
    )
    assert sorted(r.status_code for r in responses) == [401] * 5 + [429] * 7
    assert all(int(r.headers["retry-after"]) > 0 for r in responses if r.status_code == 429)


async def test_unknown_username_is_locked_the_same_way(client: httpx.AsyncClient) -> None:
    # No difference between existing and missing accounts (no enumeration).
    for _ in range(5):
        await client.post(f"{AUTH}/login", json={"username": "ghost", "password": "x" * 12})
    response = await client.post(f"{AUTH}/login", json={"username": "ghost", "password": "x" * 12})
    assert response.status_code == 429


async def test_ip_is_locked_after_twenty_failures(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    for i in range(20):
        response = await client.post(
            f"{AUTH}/login", json={"username": f"guess{i}", "password": random_password()}
        )
        assert response.status_code == 401

    assert (await start_login(client, admin)).status_code == 429
    async with extra_client(app, client_ip="10.99.0.1") as other:
        assert (await start_login(other, admin)).status_code == 200


@pytest.mark.usefixtures("client")  # runs the app lifespan
async def test_session_id_changes_on_every_login(
    app: FastAPI, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    # The browser already carries a session id chosen by an attacker.
    planted = {"Cookie": f"{SESSION_COOKIE}=attacker-chosen-session-id-0123456789abcdef"}
    issued: list[str] = []
    async with extra_client(app) as browser:
        for _ in range(2):
            clock.advance(30)
            done = await browser.post(
                f"{AUTH}/login",
                headers=planted,
                json={"username": admin.username, "password": admin.password},
            )
            issued.append(done.cookies[SESSION_COOKIE])
        attacker_view = await browser.get(f"{AUTH}/session", headers=planted)

    assert len({planted["Cookie"].split("=", 1)[1], *issued}) == 3
    assert attacker_view.status_code == 401


async def test_unknown_usernames_are_not_audited_in_clear_text(
    client: httpx.AsyncClient, audit: AuditRecorder
) -> None:
    # Someone typed the password into the username field.
    typed = "my.secret-password.2026"
    await client.post(f"{AUTH}/login", json={"username": typed, "password": random_password()})
    event = audit.find("auth.login", AuditOutcome.DENIED)[0]
    assert event.actor_username is None
    assert event.details["attempted_username_sha256"] == sha256_hex(typed)[:16]
    assert typed not in repr(audit.events)


async def test_password_hash_is_upgraded_on_login(
    settings: Settings, clock: FakeClock, audit: AuditRecorder, services: Services
) -> None:
    admin = await create_admin(settings, clock)  # hashed with t=1
    stronger = settings.model_copy(update={"argon2_time_cost": 2})
    app = create_app(stronger, clock=clock, audit_listeners=[audit])
    try:
        async with app_client(app) as client:
            assert (await start_login(client, admin)).status_code == 200
            assert (await start_login(client, admin)).status_code == 200  # new hash works
        conn = await services.pg_connect()
        try:
            stored = await conn.fetchval("SELECT password_hash FROM users WHERE id = $1", admin.id)
        finally:
            await conn.close()
        assert ",t=2," in stored
    finally:
        await services.reset()
