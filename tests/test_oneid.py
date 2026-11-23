"""OneID template: the flow around the (not yet implemented) OneID client."""

import secrets
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError

from app.audit.sink import AuditOutcome
from app.auth.dependencies import SESSION_COOKIE
from app.auth.oneid import OneIdError, OneIdIdentity
from app.auth.router import ONEID_STATE_COOKIE
from app.main import create_app
from app.settings import Settings
from tests.auth_helpers import AUTH, create_admin, totp_code
from tests.conftest import AuditRecorder, FakeClock, Services
from tests.helpers import FRONTEND_ORIGIN, app_client, extra_client

ONEID_AUTHORIZE = "https://oneid.test/authorize"


def random_pinfl() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(14))


class FakeOneIdClient:
    def __init__(self) -> None:
        self.codes: dict[str, str] = {}  # code -> PINFL
        self.closed = False

    def authorization_url(self, state: str) -> str:
        return f"{ONEID_AUTHORIZE}?state={state}"

    async def exchange_code(self, code: str) -> OneIdIdentity:
        if code not in self.codes:
            raise OneIdError("unknown code")
        return OneIdIdentity(pinfl=self.codes[code])

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture
def oneid_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "oneid_enabled": True,
            "oneid_client_id": "admin-bff-test",
            "oneid_client_secret": SecretStr(secrets.token_urlsafe(24)),
            "oneid_redirect_uri": "https://admin-api.test.uz/api/v1/auth/oneid/callback",
        }
    )


@pytest.fixture
def oneid() -> FakeOneIdClient:
    return FakeOneIdClient()


@pytest.fixture
async def oneid_client(
    oneid_settings: Settings,
    oneid: FakeOneIdClient,
    clock: FakeClock,
    audit: AuditRecorder,
    services: Services,
) -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient]]:
    app = create_app(oneid_settings, clock=clock, audit_sink=audit, oneid_client=oneid)
    async with app_client(app) as client:
        yield app, client
    await services.reset()
    assert oneid.closed


async def _start(client: httpx.AsyncClient) -> str:
    response = await client.get(f"{AUTH}/oneid/start")
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(ONEID_AUTHORIZE)
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{ONEID_STATE_COOKIE}=")
    for attribute in ("SameSite=lax", "HttpOnly", "Secure"):
        assert attribute in cookie
    state = parse_qs(urlsplit(location).query)["state"][0]
    assert client.cookies.get(ONEID_STATE_COOKIE) == state
    return state


def _error_redirect(response: httpx.Response) -> bool:
    return response.status_code == 302 and response.headers["location"] == (
        f"{FRONTEND_ORIGIN}/login?error=oneid_failed"
    )


async def test_oneid_is_off_by_default(client: httpx.AsyncClient) -> None:
    for path in ("start", "callback?code=x&state=y"):
        response = await client.get(f"{AUTH}/oneid/{path}")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


async def test_oneid_login_then_totp(
    oneid_client: tuple[FastAPI, httpx.AsyncClient],
    oneid: FakeOneIdClient,
    oneid_settings: Settings,
    clock: FakeClock,
) -> None:
    _, client = oneid_client
    pinfl = random_pinfl()
    admin = await create_admin(oneid_settings, clock, methods=("password", "oneid"), pinfl=pinfl)
    oneid.codes["good-code"] = pinfl

    state = await _start(client)
    callback = await client.get(
        f"{AUTH}/oneid/callback", params={"code": "good-code", "state": state}
    )
    assert callback.status_code == 302
    location = callback.headers["location"]
    assert location.startswith(f"{FRONTEND_ORIGIN}/login/mfa#mfa_token=")
    assert SESSION_COOKIE not in callback.cookies  # TOTP is still required
    mfa_token = location.split("#mfa_token=", 1)[1]

    done = await client.post(
        f"{AUTH}/mfa", json={"mfa_token": mfa_token, "code": totp_code(admin, clock)}
    )
    assert done.status_code == 200
    session = await client.get(f"{AUTH}/session")
    assert session.json()["auth_method"] == "oneid"
    assert session.json()["username"] == admin.username


async def test_oneid_without_totp_starts_a_setup_session(
    oneid_client: tuple[FastAPI, httpx.AsyncClient],
    oneid: FakeOneIdClient,
    oneid_settings: Settings,
    clock: FakeClock,
) -> None:
    _, client = oneid_client
    pinfl = random_pinfl()
    await create_admin(oneid_settings, clock, methods=("oneid",), pinfl=pinfl, totp=False)
    oneid.codes["code"] = pinfl

    state = await _start(client)
    callback = await client.get(f"{AUTH}/oneid/callback", params={"code": "code", "state": state})
    assert callback.headers["location"] == f"{FRONTEND_ORIGIN}/login/setup"
    session = (await client.get(f"{AUTH}/session")).json()
    # A OneID-only admin has no password, so only TOTP enrollment is pending.
    assert session["pending"] == ["totp_enrollment"]


async def test_oneid_state_must_match_the_browser_and_is_single_use(
    oneid_client: tuple[FastAPI, httpx.AsyncClient],
    oneid: FakeOneIdClient,
    oneid_settings: Settings,
    clock: FakeClock,
    audit: AuditRecorder,
) -> None:
    app, client = oneid_client
    pinfl = random_pinfl()
    await create_admin(oneid_settings, clock, methods=("oneid",), pinfl=pinfl)
    oneid.codes["code"] = pinfl

    state = await _start(client)
    wrong = await client.get(f"{AUTH}/oneid/callback", params={"code": "code", "state": "x" * 43})
    assert _error_redirect(wrong)

    # Another browser (no state cookie) cannot finish this login.
    async with extra_client(app) as other:
        stolen = await other.get(f"{AUTH}/oneid/callback", params={"code": "code", "state": state})
        assert _error_redirect(stolen)

    state = await _start(client)
    first = await client.get(f"{AUTH}/oneid/callback", params={"code": "code", "state": state})
    assert first.headers["location"].startswith(f"{FRONTEND_ORIGIN}/login/mfa#")
    client.cookies.set(ONEID_STATE_COOKIE, state, domain="testserver")
    replay = await client.get(f"{AUTH}/oneid/callback", params={"code": "code", "state": state})
    assert _error_redirect(replay)
    assert audit.find("auth.login", AuditOutcome.DENIED)


async def test_oneid_rejects_unknown_or_not_allowed_admins(
    oneid_client: tuple[FastAPI, httpx.AsyncClient],
    oneid: FakeOneIdClient,
    oneid_settings: Settings,
    clock: FakeClock,
    audit: AuditRecorder,
) -> None:
    _, client = oneid_client
    password_only = random_pinfl()
    await create_admin(oneid_settings, clock, methods=("password",), pinfl=password_only)
    inactive = random_pinfl()
    await create_admin(oneid_settings, clock, methods=("oneid",), pinfl=inactive, active=False)
    oneid.codes |= {"unknown": random_pinfl(), "password-only": password_only, "inactive": inactive}

    for code in ("unknown", "password-only", "inactive", "rejected-by-oneid"):
        state = await _start(client)
        response = await client.get(f"{AUTH}/oneid/callback", params={"code": code, "state": state})
        assert _error_redirect(response), code
    reasons = [e.details.get("reason") for e in audit.find("auth.login", AuditOutcome.DENIED)]
    assert reasons == ["unknown_pinfl", "method_not_allowed", "inactive", "oneid_error"]


async def test_enabled_oneid_without_a_client_stops_startup(oneid_settings: Settings) -> None:
    app = create_app(oneid_settings)
    with pytest.raises(RuntimeError, match="OneID client is not implemented"):
        async with app_client(app):
            pass


def test_oneid_settings_are_required_when_enabled(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="ONEID_ENABLED requires"):
        Settings(_env_file=None, app_env="test", oneid_enabled=True)


def test_oneid_identity_rejects_a_bad_pinfl() -> None:
    for bad in ("123", "1234567890123a", "١٢٣٤٥٦٧٨٩٠١٢٣٤"):
        with pytest.raises(OneIdError):
            OneIdIdentity(pinfl=bad)
