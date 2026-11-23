"""Section 9 / 12: passwords, codes, tokens and cookies never reach the logs."""

import io
from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI

from app.auth.dependencies import SESSION_COOKIE
from app.core.logging import configure_logging
from app.main import create_app
from app.settings import Settings
from tests.auth_helpers import AUTH, create_admin, random_password, totp_code
from tests.conftest import FakeClock, Services
from tests.helpers import app_client


@pytest.fixture
async def logged_app(
    settings: Settings, clock: FakeClock, services: Services
) -> AsyncIterator[tuple[FastAPI, io.StringIO]]:
    app = create_app(settings, clock=clock)  # the real audit sink: DB and its log copy
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    yield app, stream
    await services.reset()


async def test_auth_secrets_are_not_logged(
    logged_app: tuple[FastAPI, io.StringIO], settings: Settings, clock: FakeClock
) -> None:
    app, stream = logged_app
    admin = await create_admin(settings, clock)
    wrong_password = random_password()
    async with app_client(app) as client:
        await client.post(
            f"{AUTH}/login", json={"username": admin.username, "password": wrong_password}
        )
        start = await client.post(
            f"{AUTH}/login", json={"username": admin.username, "password": admin.password}
        )
        mfa_token = start.json()["mfa_token"]
        code = totp_code(admin, clock)
        done = await client.post(f"{AUTH}/mfa", json={"mfa_token": mfa_token, "code": code})
        csrf_token = done.json()["csrf_token"]
        session_id = client.cookies.get(SESSION_COOKIE)
        await client.post(f"{AUTH}/logout", headers={"X-CSRF-Token": csrf_token})

    output = stream.getvalue()
    assert '"action": "auth.login"' in output  # audit events are logged
    assert session_id
    for secret in (admin.password, wrong_password, mfa_token, csrf_token, session_id):
        assert secret not in output
    # Six digits may occur by chance inside a timestamp; a logged code would be a value.
    assert f'"{code}"' not in output
