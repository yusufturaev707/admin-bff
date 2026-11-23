"""GET /api/v1/audit and what gets audited (sections 9 and 10)."""

import io
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from fastapi import APIRouter, FastAPI

from app.audit.sink import AuditOutcome
from app.core.errors import AppError
from app.core.logging import configure_logging
from app.core.pagination import decode_cursor, encode_cursor
from app.core.time import isoformat_z
from app.main import create_app
from app.settings import Settings
from tests.conftest import FakeClock, Services
from tests.helpers.audit import records, write_events
from tests.helpers.auth import AUTH, Admin, create_admin, login, start_login
from tests.helpers.client import app_client, extra_client
from tests.helpers.rbac import make_admin_with, make_superadmin

AUDIT = "/api/v1/audit"
ADMIN = "/api/v1/admin"


def _request_id(response: httpx.Response) -> str:
    return response.headers["X-Request-ID"]


async def _signed_in_superadmin(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> tuple[Admin, dict[str, str]]:
    superadmin = await make_superadmin(settings, clock)
    return superadmin, {"X-CSRF-Token": await login(client, superadmin, clock)}


# --- what is audited -------------------------------------------------------------


async def test_every_write_request_is_audited(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    _, h = await _signed_in_superadmin(client, settings, clock)
    writes: list[httpx.Response] = []

    async def call(method: str, url: str, **kwargs: object) -> httpx.Response:
        response = await client.request(method, url, headers=h, **kwargs)  # type: ignore[arg-type]
        writes.append(response)
        return response

    role = await call(
        "POST", f"{ADMIN}/roles", json={"name": "operator", "permissions": ["admin:users:read"]}
    )
    role_id = role.json()["id"]
    await call("PATCH", f"{ADMIN}/roles/{role_id}", json={"description": "yangi"})
    user = await call(
        "POST",
        f"{ADMIN}/users",
        json={
            "username": "operator_1",
            "auth_methods": ["password"],
            "role_ids": [role_id],
        },
    )
    user_id = user.json()["id"]
    await call("PATCH", f"{ADMIN}/users/{user_id}", json={"full_name": "Aliyev Vali"})
    await call("PUT", f"{ADMIN}/users/{user_id}/roles", json={"role_ids": []})
    await call("POST", f"{ADMIN}/users/{user_id}/reset-password")
    await call("POST", f"{ADMIN}/users/{user_id}/unlock")
    await call("DELETE", f"{ADMIN}/roles/{role_id}")
    # Requests that fail are audited too.
    invalid = await call("POST", f"{ADMIN}/roles", json={"name": ""})
    missing = await call("DELETE", f"{ADMIN}/roles/{uuid.uuid4()}")
    await call("POST", f"{AUTH}/password", json={"old_password": "x" * 16, "new_password": "y"})
    await call("POST", f"{AUTH}/logout")

    assert [r.status_code for r in writes] == [
        201, 200, 201, 200, 200, 200, 204, 204, 422, 404, 422, 204
    ]  # fmt: skip
    for response in writes:
        found = await records(settings, request_id=_request_id(response))
        assert found, f"{response.request.method} {response.request.url} was not audited"

    [record] = await records(settings, request_id=_request_id(invalid))
    assert (record.action, record.outcome, record.status_code) == ("http.request", "error", 422)
    assert record.details == {"method": "POST", "path": f"{ADMIN}/roles"}
    assert record.actor_username is not None
    assert record.system_id == "admin"
    [record] = await records(settings, request_id=_request_id(missing))
    assert (record.action, record.status_code, record.resource) == ("http.request", 404, None)


async def test_changes_are_audited_with_before_and_after(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    _, h = await _signed_in_superadmin(client, settings, clock)
    role = await client.post(
        f"{ADMIN}/roles", json={"name": "operator", "permissions": []}, headers=h
    )
    user = await client.post(
        f"{ADMIN}/users",
        json={
            "username": "operator_2",
            "auth_methods": ["password", "oneid"],
            "pinfl": "31201234560045",
            "role_ids": [role.json()["id"]],
        },
        headers=h,
    )
    user_id = user.json()["id"]
    await client.patch(f"{ADMIN}/users/{user_id}", json={"full_name": "Vali"}, headers=h)
    await client.put(f"{ADMIN}/users/{user_id}/roles", json={"role_ids": []}, headers=h)

    created, updated, roles = await records(settings, resource="users", resource_id=user_id)
    assert (created.action, created.system_id, created.before) == (
        "admin.user.create",
        "admin",
        None,
    )
    assert created.after["pinfl_masked"] == "3120*****0045"
    assert "31201234560045" not in str(created.after)
    assert (updated.before["full_name"], updated.after["full_name"]) == (None, "Vali")
    assert (roles.before, roles.after) == (["operator"], [])
    [role_created] = await records(settings, action="admin.role.create")
    assert role_created.resource_id == role.json()["id"]


async def test_rejected_requests_are_audited(
    app: FastAPI, client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    viewer = await make_admin_with(settings, clock, ["admin:users:read"])
    csrf = await login(client, viewer, clock)
    body = {"name": "x" * 10, "permissions": []}

    denied = await client.get(AUDIT)  # no audit:logs:read
    assert denied.status_code == 403
    [record] = await records(settings, request_id=_request_id(denied))
    assert (record.action, record.outcome, record.status_code) == ("rbac.denied", "denied", 403)
    assert (record.system_id, record.actor_id) == ("audit", viewer.id)
    assert record.details["required"] == ["audit:logs:read"]

    bad_token = await client.post(f"{ADMIN}/roles", json=body, headers={"X-CSRF-Token": "x"})
    assert bad_token.status_code == 403
    [record] = await records(settings, request_id=_request_id(bad_token))
    assert (record.action, record.status_code, record.actor_id) == ("http.request", 403, viewer.id)

    async with extra_client(app, origin="https://evil.example") as other:
        bad_origin = await other.post(f"{ADMIN}/roles", json=body, headers={"X-CSRF-Token": csrf})
    assert bad_origin.status_code == 403
    [record] = await records(settings, request_id=_request_id(bad_origin))
    assert (record.action, record.outcome, record.actor_id) == ("http.request", "denied", None)

    async with extra_client(app) as anonymous:
        no_session = await anonymous.post(f"{ADMIN}/roles", json=body)
        unknown_path = await anonymous.post("/api/v1/no-such-thing", json={})
    assert (no_session.status_code, unknown_path.status_code) == (401, 404)
    [record] = await records(settings, request_id=_request_id(no_session))
    assert (record.outcome, record.status_code) == ("denied", 401)
    assert await records(settings, request_id=_request_id(unknown_path)) == []


async def test_unfinished_setup_403_is_audited(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    newcomer = await create_admin(settings, clock, must_change_password=True)
    assert (await start_login(client, newcomer)).status_code == 200
    response = await client.get("/api/v1/me")
    assert response.status_code == 403
    [record] = await records(settings, request_id=_request_id(response))
    assert (record.action, record.actor_id, record.status_code) == (
        "http.request",
        newcomer.id,
        403,
    )
    assert record.details["method"] == "GET"


async def test_logins_are_audited_without_a_duplicate_request_record(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    admin = await create_admin(settings, clock)
    wrong = await client.post(
        f"{AUTH}/login", json={"username": admin.username, "password": "x" * 16}
    )
    assert wrong.status_code == 401
    [record] = await records(settings, request_id=_request_id(wrong))
    assert (record.action, record.outcome, record.actor_id) == ("auth.login", "denied", admin.id)
    signed_in = await start_login(client, admin)
    [record] = await records(settings, request_id=_request_id(signed_in))
    assert (record.action, record.session_hash is not None) == ("auth.login", True)


# --- the list ----------------------------------------------------------------------


async def test_list_needs_the_permission_and_paginates_with_a_cursor(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    auditor = await make_admin_with(settings, clock, ["audit:logs:read"])
    await login(client, auditor, clock)
    await write_events(settings, clock, 7, action="test.page.item")

    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, str | int] = {"action": "test.page.item", "limit": 3}
        if cursor:
            params["cursor"] = cursor
        response = await client.get(AUDIT, params=params)
        assert response.status_code == 200, response.text
        assert response.headers["Cache-Control"] == "no-store"
        page = response.json()
        seen += [item["id"] for item in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert pages == 3
    stored = [str(r.id) for r in await records(settings, action="test.page.item")]
    assert seen == list(reversed(stored))  # newest first, nothing twice, nothing missing


async def test_list_filters(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    auditor = await make_admin_with(settings, clock, ["audit:logs:read"])
    await login(client, auditor, clock)
    actor = uuid.uuid4()
    resource_id = str(uuid.uuid4())
    start = clock()
    await write_events(
        settings,
        clock,
        2,
        action="test.filter.one",
        actor_id=actor,
        actor_username="filtered_actor",
        system_id="faceid",
        resource="students",
        resource_id=resource_id,
        outcome=AuditOutcome.DENIED,
    )
    later = FakeClock()  # an hour later, without expiring the session
    later.now = start + timedelta(hours=1)
    await write_events(settings, later, 1, action="test.filter.two", request_id="req-1")

    async def ids(**params: str) -> int:
        response = await client.get(AUDIT, params=params)
        assert response.status_code == 200, response.text
        return len(response.json()["items"])

    assert await ids(actor_id=str(actor)) == 2
    assert await ids(actor_username="FILTERED_ACTOR") == 2  # case-insensitive
    assert await ids(system_id="faceid") == 2
    assert await ids(outcome="denied", action="test.filter.one") == 2
    assert await ids(resource="students", resource_id=resource_id) == 2
    assert await ids(request_id="req-1") == 1
    window = {"from": isoformat_z(start), "to": isoformat_z(start + timedelta(minutes=30))}
    assert await ids(action="test.filter.one", **window) == 2
    assert await ids(action="test.filter.two", **window) == 0

    item = (await client.get(AUDIT, params={"request_id": "req-1"})).json()["items"][0]
    assert isinstance(item["id"], str)
    assert item["ts"].endswith("Z")
    assert item["actor_ip"] == "10.20.30.40"
    assert item["outcome"] == "success"


@pytest.mark.parametrize(
    ("params", "error_type"),
    [
        ({"nope": "1"}, "unknown_parameter"),
        ({"cursor": "not-a-cursor"}, "invalid_cursor"),
        ({"from": "2026-11-23T10:00:00"}, "timezone_aware"),
        ({"from": "2026-11-23T10:00:00Z", "to": "2026-11-23T10:00:00Z"}, "invalid_range"),
        ({"limit": "101"}, "less_than_equal"),
        ({"outcome": "maybe"}, "enum"),
    ],
)
async def test_list_rejects_bad_parameters(
    client: httpx.AsyncClient,
    settings: Settings,
    clock: FakeClock,
    params: dict[str, str],
    error_type: str,
) -> None:
    auditor = await make_admin_with(settings, clock, ["audit:logs:read"])
    await login(client, auditor, clock)
    response = await client.get(AUDIT, params=params)
    assert response.status_code == 422
    assert response.json()["error"]["details"]["fields"][0]["type"] == error_type


def test_cursor_round_trip_and_garbage() -> None:
    assert decode_cursor(encode_cursor(123456)) == 123456
    # empty, not base64, "v1:-1", "v2:1", "v"
    for garbage in ("", "!!!", "djE6LTE", "djI6MQ", "dj"):
        with pytest.raises(AppError):
            decode_cursor(garbage)


# --- the request-level record itself -------------------------------------------------

crash_router = APIRouter()


@crash_router.post("/_test/audit/crash", operation_id="test_auditcrash_create")
async def crash() -> None:
    raise RuntimeError("unexpected")


@pytest.fixture
async def crash_client(
    settings: Settings, clock: FakeClock, services: Services
) -> AsyncIterator[tuple[FastAPI, httpx.AsyncClient]]:
    app = create_app(settings, clock=clock)
    app.include_router(crash_router)
    app.state.extra_public_paths = frozenset({"/_test/audit/crash"})
    async with app_client(app) as client:
        yield app, client
    await services.reset()


async def test_an_unhandled_error_is_audited(
    crash_client: tuple[FastAPI, httpx.AsyncClient], settings: Settings
) -> None:
    _, client = crash_client
    response = await client.post("/_test/audit/crash")
    assert response.status_code == 500
    [record] = await records(settings, request_id=_request_id(response))
    assert (record.action, record.outcome, record.status_code) == ("http.request", "error", 500)


async def test_a_failed_request_record_does_not_change_the_response(
    crash_client: tuple[FastAPI, httpx.AsyncClient],
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client = crash_client

    async def broken(event: object) -> None:
        raise RuntimeError("audit database is down")

    monkeypatch.setattr(app.state.audit_sink, "write", broken)
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    response = await client.post(f"{ADMIN}/roles", json={})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"
    assert "audit_request_record_failed" in stream.getvalue()
