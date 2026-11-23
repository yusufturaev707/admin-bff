"""Section 6 / 12: first sign-in (TOTP enrollment, forced password change),
recovery codes, step-up."""

from typing import Annotated

import httpx
import pyotp
from fastapi import APIRouter, Depends, FastAPI

from app.audit.sink import AuditOutcome
from app.auth.dependencies import SESSION_COOKIE, require_recent_mfa
from app.auth.sessions import SessionData
from app.settings import Settings
from tests.auth_helpers import AUTH, create_admin, login, random_password, totp_code, wrong_code
from tests.conftest import AuditRecorder, FakeClock
from tests.helpers import app_client


def csrf(token: str) -> dict[str, str]:
    return {"X-CSRF-Token": token}


async def test_first_sign_in_enrolls_totp_then_changes_password(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    admin = await create_admin(settings, clock, totp=False, must_change_password=True)

    started = await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": admin.password}
    )
    assert started.status_code == 200
    body = started.json()
    assert body["mfa_required"] is False
    assert body["setup_required"] is True
    assert body["pending"] == ["totp_enrollment", "password_change"]
    token = body["csrf_token"]
    setup_cookie = client.cookies.get(SESSION_COOKIE)

    # Until the setup is finished, only /auth/password and /auth/totp/* work.
    restricted = await client.get(f"{AUTH}/sessions")
    assert restricted.status_code == 403
    assert restricted.json()["error"]["details"]["pending"] == [
        "totp_enrollment",
        "password_change",
    ]
    assert (
        await client.post(f"{AUTH}/step-up", headers=csrf(token), json={"code": "123456"})
    ).status_code == 403
    early = await client.post(
        f"{AUTH}/password",
        headers=csrf(token),
        json={"old_password": admin.password, "new_password": random_password(), "code": "123456"},
    )
    assert early.status_code == 403

    enroll = await client.post(f"{AUTH}/totp/enroll", headers=csrf(token))
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")

    wrong = await client.post(
        f"{AUTH}/totp/confirm",
        headers=csrf(token),
        json={"code": wrong_code(pyotp.TOTP(secret).at(clock()))},
    )
    assert wrong.status_code == 422

    confirm = await client.post(
        f"{AUTH}/totp/confirm", headers=csrf(token), json={"code": pyotp.TOTP(secret).at(clock())}
    )
    assert confirm.status_code == 200
    confirmed = confirm.json()
    codes = confirmed["recovery_codes"]
    assert len(codes) == len(set(codes)) == 10
    assert confirmed["pending"] == ["password_change"]
    # Privilege change: new session id and new CSRF token.
    assert client.cookies.get(SESSION_COOKIE) != setup_cookie
    assert confirmed["csrf_token"] != token
    token = confirmed["csrf_token"]

    again = await client.post(f"{AUTH}/totp/enroll", headers=csrf(token))
    assert again.status_code == 409

    clock.advance(30)
    new_password = random_password()
    changed = await client.post(
        f"{AUTH}/password",
        headers=csrf(token),
        json={
            "old_password": admin.password,
            "new_password": new_password,
            "code": pyotp.TOTP(secret).at(clock()),
        },
    )
    assert changed.status_code == 204
    assert (await client.get(f"{AUTH}/session")).status_code == 401

    # Normal sign-in now: password, then a recovery code instead of TOTP.
    async def sign_in_with_recovery_code(code: str) -> httpx.Response:
        start = await client.post(
            f"{AUTH}/login", json={"username": admin.username, "password": new_password}
        )
        assert start.json()["mfa_required"] is True
        return await client.post(
            f"{AUTH}/mfa", json={"mfa_token": start.json()["mfa_token"], "recovery_code": code}
        )

    used = await sign_in_with_recovery_code(codes[0].lower())
    assert used.status_code == 200
    assert used.json()["setup_required"] is False
    assert (await client.get(f"{AUTH}/sessions")).status_code == 200
    assert audit.find("auth.recovery_code.use")[0].details["remaining"] == 9

    reused = await sign_in_with_recovery_code(codes[0])
    assert reused.status_code == 422
    assert reused.json()["error"]["details"]["fields"][0]["loc"] == ["body", "recovery_code"]


async def test_step_up_refreshes_mfa_time(
    app: FastAPI, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    router = APIRouter()

    @router.post("/_test/dangerous", operation_id="test_dangerous_submit")
    async def dangerous(
        session: Annotated[SessionData, Depends(require_recent_mfa(300))],
    ) -> dict[str, str]:
        return {"user": session.username}

    app.include_router(router)
    admin = await create_admin(settings, clock)
    async with app_client(app) as client:
        token = await login(client, admin, clock)
        assert (await client.post("/_test/dangerous", headers=csrf(token))).status_code == 200

        clock.advance(301)
        stale = await client.post("/_test/dangerous", headers=csrf(token))
        assert stale.status_code == 401
        assert stale.json()["error"]["code"] == "step_up_required"

        wrong = await client.post(
            f"{AUTH}/step-up",
            headers=csrf(token),
            json={"code": wrong_code(totp_code(admin, clock))},
        )
        assert wrong.status_code == 422

        step_up = await client.post(
            f"{AUTH}/step-up", headers=csrf(token), json={"code": totp_code(admin, clock)}
        )
        assert step_up.status_code == 200
        assert step_up.json()["mfa_at"].endswith("Z")
        assert (await client.post("/_test/dangerous", headers=csrf(token))).status_code == 200
        assert audit.find("auth.step_up", AuditOutcome.SUCCESS)
