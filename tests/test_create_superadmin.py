"""scripts/create_superadmin.py: the first superadmin (section 6)."""

import asyncio
import getpass

import httpx
import pytest

from app.settings import Settings
from scripts import create_superadmin as script
from tests.auth_helpers import AUTH, random_password
from tests.conftest import Services


async def test_superadmin_signs_in_with_every_permission(
    client: httpx.AsyncClient, settings: Settings, services: Services
) -> None:
    password = random_password()
    user_id = await script.create_superadmin(settings, "chief", password)
    # A second superadmin reuses the system role.
    await script.create_superadmin(settings, "deputy", random_password())

    login = await client.post(f"{AUTH}/login", json={"username": "chief", "password": password})
    assert login.status_code == 200
    assert login.json()["pending"] == ["password_change"]
    new_password = random_password()
    changed = await client.post(
        f"{AUTH}/password",
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
        json={"old_password": password, "new_password": new_password},
    )
    assert changed.status_code == 204
    relogin = await client.post(
        f"{AUTH}/login", json={"username": "chief", "password": new_password}
    )
    assert relogin.status_code == 200
    me = (await client.get("/api/v1/me")).json()
    assert me["permissions"] == ["*:*:*"]
    assert [role["name"] for role in me["roles"]] == ["superadmin"]

    conn = await services.pg_connect()
    try:
        audited = await conn.fetch(
            "SELECT actor_username, resource_id FROM audit_log "
            "WHERE action = 'admin.superadmin.create' ORDER BY id"
        )
        roles = await conn.fetchval("SELECT count(*) FROM roles WHERE name = 'superadmin'")
    finally:
        await conn.close()
    assert [row["actor_username"] for row in audited] == ["script", "script"]
    assert audited[0]["resource_id"] == str(user_id)
    assert roles == 1


def test_main_checks_the_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings: Settings,
    services: Services,
) -> None:
    answers: list[str] = []
    monkeypatch.setattr(getpass, "getpass", lambda prompt: answers.pop(0))
    monkeypatch.setattr(script, "load_settings", lambda: settings)
    strong = random_password()

    def run(username: str, *typed: str) -> tuple[int, str]:
        answers[:] = list(typed)
        code = script.main(["--username", username])
        assert answers == []  # asked exactly as many times as expected
        return code, capsys.readouterr().err

    try:
        assert run(" Chief.Admin ", strong, strong) == (0, "")
        code, err = run("chief.admin", strong, strong)
        assert (code, "allaqachon bor" in err) == (1, True)
        code, err = run("x")  # the password is not even asked
        assert (code, "noto'g'ri" in err) == (2, True)
        code, err = run("other_admin", strong, strong + "x")
        assert (code, "mos kelmadi" in err) == (1, True)
        code, err = run("other_admin", "short", "short")
        assert (code, "kamida 12" in err) == (1, True)
    finally:
        asyncio.run(services.reset())
