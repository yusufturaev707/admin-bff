"""TOTP_REQUIRED=false: password alone, no step-up (the owner's decision)."""

from collections.abc import AsyncIterator

import httpx
import pytest

from app.main import create_app
from app.settings import Settings
from tests.auth_helpers import AUTH, create_admin, random_password, start_login
from tests.conftest import AuditRecorder, FakeClock, Services
from tests.helpers import app_client
from tests.rbac_helpers import make_superadmin


@pytest.fixture
async def no_totp(
    settings: Settings, clock: FakeClock, audit: AuditRecorder, services: Services
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(
        settings.model_copy(update={"totp_required": False}),
        clock=clock,
        audit_listeners=[audit],
    )
    async with app_client(app) as client:
        yield client
    await services.reset()


async def test_password_alone_opens_a_full_session(
    no_totp: httpx.AsyncClient, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    superadmin = await make_superadmin(settings, clock)  # has TOTP: it is not asked
    response = await start_login(no_totp, superadmin)
    assert response.status_code == 200
    body = response.json()
    assert (body["mfa_required"], body["setup_required"], body["pending"]) == (False, False, [])
    assert (await no_totp.get("/api/v1/me")).status_code == 200
    login_events = audit.find("auth.login")
    assert login_events[-1].details["totp_required"] is False

    # No step-up either, however long ago the sign-in was.
    clock.advance(20 * 60)
    created = await no_totp.post(
        "/api/v1/admin/roles",
        json={"name": "no_totp_role", "permissions": []},
        headers={"X-CSRF-Token": body["csrf_token"]},
    )
    assert created.status_code == 201, created.text
    assert "const TOTP = false;" in (await no_totp.get("/api/v1/docs/init.js")).text


async def test_first_sign_in_only_changes_the_password(
    no_totp: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    newcomer = await create_admin(settings, clock, totp=False, must_change_password=True)
    body = (await start_login(no_totp, newcomer)).json()
    assert (body["setup_required"], body["pending"]) == (True, ["password_change"])
    changed = await no_totp.post(
        f"{AUTH}/password",
        json={"old_password": newcomer.password, "new_password": random_password()},
        headers={"X-CSRF-Token": body["csrf_token"]},
    )
    assert changed.status_code == 204, changed.text


async def test_the_code_is_still_needed_when_totp_is_on(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock, totp=False, must_change_password=True)
    body = (await start_login(client, admin)).json()
    assert body["pending"] == ["totp_enrollment", "password_change"]
    response = await client.post(
        f"{AUTH}/password",
        json={"old_password": admin.password, "new_password": random_password()},
        headers={"X-CSRF-Token": body["csrf_token"]},
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"]["fields"][0]["type"] == "invalid_code"


def test_production_may_run_without_totp(settings: Settings) -> None:
    production = Settings.model_validate(
        {
            **settings.model_dump(),
            "app_env": "production",
            "argon2_time_cost": 2,
            "argon2_memory_cost_kib": 19456,
            "totp_required": False,
        }
    )
    assert not production.totp_required
