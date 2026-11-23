"""Section 6 / 12: the first sign-in changes the password; nothing else works until then."""

import httpx

from app.audit.sink import AuditOutcome
from app.auth.dependencies import SESSION_COOKIE
from app.settings import Settings
from tests.conftest import AuditRecorder, FakeClock
from tests.helpers.auth import AUTH, create_admin, random_password, start_login


async def test_first_sign_in_changes_the_password(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    admin = await create_admin(settings, clock, must_change_password=True)
    started = await start_login(client, admin)
    assert started.status_code == 200
    body = started.json()
    assert (body["setup_required"], body["pending"]) == (True, ["password_change"])
    headers = {"X-CSRF-Token": body["csrf_token"]}

    # Until the setup is finished, only /auth/* works.
    restricted = await client.get("/api/v1/me")
    assert restricted.status_code == 403
    assert restricted.json()["error"]["details"]["pending"] == ["password_change"]
    assert (await client.get(f"{AUTH}/session")).status_code == 200

    wrong = await client.post(
        f"{AUTH}/password",
        json={"old_password": "x" * 16, "new_password": random_password()},
        headers=headers,
    )
    assert wrong.status_code == 422
    assert wrong.json()["error"]["details"]["fields"][0]["type"] == "invalid_password"
    weak = await client.post(
        f"{AUTH}/password",
        json={"old_password": admin.password, "new_password": "short"},
        headers=headers,
    )
    assert weak.json()["error"]["details"]["fields"][0]["type"] == "password_too_short"
    same = await client.post(
        f"{AUTH}/password",
        json={"old_password": admin.password, "new_password": admin.password},
        headers=headers,
    )
    assert same.json()["error"]["details"]["fields"][0]["type"] == "password_reused"

    new_password = random_password()
    changed = await client.post(
        f"{AUTH}/password",
        json={"old_password": admin.password, "new_password": new_password},
        headers=headers,
    )
    assert changed.status_code == 204
    # Every session ends, the cookie is cleared.
    assert client.cookies.get(SESSION_COOKIE) is None
    assert audit.find("auth.password.change", AuditOutcome.SUCCESS)

    again = await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": new_password}
    )
    assert again.json()["pending"] == []
    assert (await client.get("/api/v1/me")).status_code == 200
