"""Section 7 / 12: RBAC over the admin API."""

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.sink import AuditOutcome
from app.rbac.models import SUPERADMIN_ROLE
from app.rbac.service import AdminService
from app.settings import Settings
from tests.auth_helpers import AUTH, Admin, create_admin, login, random_password
from tests.conftest import AuditRecorder, FakeClock
from tests.helpers import extra_client
from tests.rbac_helpers import grant, make_admin_with, make_role, make_superadmin

ADMIN = "/api/v1/admin"


class Browser:
    """One signed-in admin: a client plus its CSRF token."""

    def __init__(self, client: httpx.AsyncClient, csrf: str) -> None:
        self.client = client
        self.headers = {"X-CSRF-Token": csrf}

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.client.get(path, **kwargs)

    async def send(self, method: str, path: str, json: Any = None) -> httpx.Response:
        return await self.client.request(method, path, json=json, headers=self.headers)


@pytest.fixture
async def browsers(app: FastAPI, client: httpx.AsyncClient, clock: FakeClock) -> AsyncIterator[Any]:
    """`await browsers(admin)` signs `admin` in with its own client."""
    opened: list[httpx.AsyncClient] = []

    async def open_for(admin: Admin) -> Browser:
        browser_client = extra_client(app)
        opened.append(browser_client)
        return Browser(browser_client, await login(browser_client, admin, clock))

    yield open_for
    for c in opened:
        await c.aclose()


async def test_missing_permission_is_forbidden_and_audited(
    browsers: Any, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    reader = await browsers(await make_admin_with(settings, clock, ["admin:users:read"]))
    assert (await reader.get(f"{ADMIN}/users")).status_code == 200
    response = await reader.send("POST", f"{ADMIN}/roles", {"name": "x1", "permissions": []})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    denied = audit.find("rbac.denied", AuditOutcome.DENIED)
    assert denied[-1].details["required"] == ["admin:roles:write"]


async def test_wildcard_grants(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    viewer = await browsers(await make_admin_with(settings, clock, ["admin:*:read"]))
    for path in ("/users", "/roles", "/permissions"):
        assert (await viewer.get(ADMIN + path)).status_code == 200, path
    created = await viewer.send("POST", f"{ADMIN}/roles", {"name": "x2", "permissions": []})
    assert created.status_code == 403


async def test_role_created_by_superadmin_is_applied(
    app: FastAPI, browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    catalogue = (await boss.get(f"{ADMIN}/permissions")).json()["groups"]
    assert catalogue[0]["system_id"] == "admin"
    assert all(p["description"] for p in catalogue[0]["permissions"])

    role = await boss.send(
        "POST",
        f"{ADMIN}/roles",
        {"name": "auditor", "description": "faqat ko'rish", "permissions": ["admin:users:read"]},
    )
    assert role.status_code == 201
    role_id = role.json()["id"]

    # A new admin created through the API gets a one-time temporary password
    # and must change the password first.
    created = await boss.send(
        "POST",
        f"{ADMIN}/users",
        {
            "username": "new_auditor",
            "role_ids": [role_id],
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["must_change_password"] is True
    assert body["roles"] == [{"id": role_id, "name": "auditor"}]
    async with extra_client(app) as newcomer:
        first = await newcomer.post(
            f"{AUTH}/login",
            json={"username": "new_auditor", "password": body["initial_password"]},
        )
        assert first.json()["pending"] == ["password_change"]

    # An existing admin given the role can read admins, nothing more.
    operator = await create_admin(settings, clock)
    assigned = await boss.send("PUT", f"{ADMIN}/users/{operator.id}/roles", {"role_ids": [role_id]})
    assert assigned.status_code == 200
    me = await browsers(operator)
    assert (await me.get(f"{ADMIN}/users")).status_code == 200
    assert (await me.get(f"{ADMIN}/roles")).status_code == 403


async def test_role_change_applies_on_the_next_request(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    role_id = await make_role(settings, ["admin:users:read"])
    operator = await create_admin(settings, clock)
    await grant(settings, operator.id, [role_id])
    me = await browsers(operator)
    assert (await me.get(f"{ADMIN}/users")).status_code == 200

    changed = await boss.send(
        "PATCH", f"{ADMIN}/roles/{role_id}", {"permissions": ["admin:roles:read"]}
    )
    assert changed.status_code == 200
    # Same session, very next request: the new permissions apply.
    assert (await me.get(f"{ADMIN}/users")).status_code == 403
    assert (await me.get(f"{ADMIN}/roles")).status_code == 200


async def test_role_assignment_ends_the_admins_sessions(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    operator = await make_admin_with(settings, clock, ["admin:users:read"])
    me = await browsers(operator)
    new_role = await make_role(settings, ["admin:roles:read"])
    response = await boss.send(
        "PUT", f"{ADMIN}/users/{operator.id}/roles", {"role_ids": [str(new_role)]}
    )
    assert response.status_code == 200
    assert (await me.get(f"{AUTH}/session")).status_code == 401


async def test_no_privilege_escalation(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    superadmin = await make_superadmin(settings, clock)
    manager = await make_admin_with(
        settings,
        clock,
        ["admin:users:read", "admin:users:write", "admin:roles:read", "admin:roles:write"],
    )
    plain = await make_admin_with(settings, clock, [])
    me = await browsers(manager)

    def forbidden(response: httpx.Response) -> bool:
        return response.status_code == 403 and response.json()["error"]["code"] == "forbidden"

    # Cannot create a role with a permission it does not hold...
    assert forbidden(
        await me.send(
            "POST", f"{ADMIN}/roles", {"name": "sec", "permissions": ["admin:users:security"]}
        )
    )
    assert forbidden(
        await me.send("POST", f"{ADMIN}/roles", {"name": "all", "permissions": ["admin:*:*"]})
    )
    # ...but can create one within its own rights.
    ok = await me.send(
        "POST", f"{ADMIN}/roles", {"name": "reader", "permissions": ["admin:users:read"]}
    )
    assert ok.status_code == 201

    roles = {r["name"]: r["id"] for r in (await me.get(f"{ADMIN}/roles")).json()}
    # Cannot hand out the superadmin role.
    assert forbidden(
        await me.send("PUT", f"{ADMIN}/users/{plain.id}/roles", {"role_ids": [roles["superadmin"]]})
    )
    # Cannot change itself or anyone above it.
    assert forbidden(
        await me.send("PUT", f"{ADMIN}/users/{manager.id}/roles", {"role_ids": [roles["reader"]]})
    )
    assert forbidden(await me.send("PATCH", f"{ADMIN}/users/{manager.id}", {"is_active": False}))
    assert forbidden(await me.send("PATCH", f"{ADMIN}/users/{superadmin.id}", {"is_active": False}))
    # Allowed: within its own rights, on an admin below it.
    done = await me.send("PUT", f"{ADMIN}/users/{plain.id}/roles", {"role_ids": [roles["reader"]]})
    assert done.status_code == 200
    # Own name is fine.
    assert (
        await me.send("PATCH", f"{ADMIN}/users/{manager.id}", {"full_name": "Menejer"})
    ).status_code == 200


async def test_last_superadmin_is_protected(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    only = await make_superadmin(settings, clock)
    # Another admin with every permission, but not the superadmin role.
    peer = await make_admin_with(settings, clock, ["*:*:*"])
    me = await browsers(peer)
    for method, path, body in (
        ("PUT", f"{ADMIN}/users/{only.id}/roles", {"role_ids": []}),
        ("PATCH", f"{ADMIN}/users/{only.id}", {"is_active": False}),
    ):
        response = await me.send(method, path, body)
        assert response.status_code == 409, path
        assert response.json()["error"]["code"] == "conflict"


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [("PATCH", "", {"is_active": False}), ("PUT", "/roles", {"role_ids": []})],
)
async def test_two_superadmins_cannot_remove_each_other_at_once(
    browsers: Any,
    settings: Settings,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    suffix: str,
    body: dict[str, Any],
) -> None:
    role_id = await make_role(settings, ["*:*:*"], name=SUPERADMIN_ROLE, system=True)
    first = await create_admin(settings, clock)
    second = await create_admin(settings, clock)
    for admin in (first, second):
        await grant(settings, admin.id, [role_id])
    one, other = await browsers(first), await browsers(second)

    # Each request would read "two superadmins are active" before the other one
    # commits, unless these changes are serialised.
    count_superadmins = AdminService._active_superadmins

    async def slow(service: AdminService, db: AsyncSession) -> set[uuid.UUID]:
        found = await count_superadmins(service, db)
        await asyncio.sleep(0.2)
        return found

    monkeypatch.setattr(AdminService, "_active_superadmins", slow)
    responses = await asyncio.gather(
        one.send(method, f"{ADMIN}/users/{second.id}{suffix}", body),
        other.send(method, f"{ADMIN}/users/{first.id}{suffix}", body),
    )
    assert sorted(r.status_code for r in responses) == [200, 409]


async def test_role_rules(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    roles = {r["name"]: r for r in (await boss.get(f"{ADMIN}/roles")).json()}
    system = roles["superadmin"]
    assert system["is_system"] is True

    assert (await boss.send("DELETE", f"{ADMIN}/roles/{system['id']}")).status_code == 409
    assert (
        await boss.send("PATCH", f"{ADMIN}/roles/{system['id']}", {"name": "renamed"})
    ).status_code == 409
    reserved = await boss.send("POST", f"{ADMIN}/roles", {"name": "SuperAdmin", "permissions": []})
    assert reserved.status_code == 409
    typo = await boss.send(
        "POST", f"{ADMIN}/roles", {"name": "typo", "permissions": ["admin:userz:read"]}
    )
    assert typo.status_code == 422
    assert typo.json()["error"]["details"]["fields"][0]["type"] == "unknown_permission"

    used = await make_role(settings, ["admin:users:read"])
    await grant(settings, (await create_admin(settings, clock)).id, [used])
    assert (await boss.send("DELETE", f"{ADMIN}/roles/{used}")).status_code == 409
    unused = await make_role(settings, ["admin:users:read"])
    assert (await boss.send("DELETE", f"{ADMIN}/roles/{unused}")).status_code == 204
    assert (await boss.get(f"{ADMIN}/roles/{unused}")).status_code == 404


async def test_user_listing(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    superadmin = await make_superadmin(settings, clock)  # username "admin_<hex>"
    boss = await browsers(superadmin)
    for name in ("alpha_one", "alpha_two", "beta_one"):
        await create_admin(settings, clock, username=name)

    page = (await boss.get(f"{ADMIN}/users", params={"page_size": 2, "sort": "username"})).json()
    assert page["total"] == 4
    assert page["page_size"] == 2
    assert [u["username"] for u in page["items"]] == [superadmin.username, "alpha_one"]
    second = (await boss.get(f"{ADMIN}/users", params={"page_size": 2, "page": 2})).json()
    assert [u["username"] for u in second["items"]] == ["alpha_two", "beta_one"]

    found = (await boss.get(f"{ADMIN}/users", params={"q": "alpha"})).json()
    assert sorted(u["username"] for u in found["items"]) == ["alpha_one", "alpha_two"]
    newest = (await boss.get(f"{ADMIN}/users", params={"sort": "-username"})).json()
    assert newest["items"][0]["username"] == "beta_one"

    unknown = await boss.get(f"{ADMIN}/users", params={"is_activ": "true"})
    assert unknown.status_code == 422
    assert unknown.json()["error"]["details"]["fields"][0]["type"] == "unknown_parameter"
    too_big = await boss.get(f"{ADMIN}/users", params={"page_size": 101})
    assert too_big.status_code == 422


async def test_blocking_ends_sessions_and_sign_in(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    operator = await make_admin_with(settings, clock, ["admin:users:read"])
    me = await browsers(operator)
    blocked = await boss.send("PATCH", f"{ADMIN}/users/{operator.id}", {"is_active": False})
    assert blocked.status_code == 200
    assert blocked.json()["is_active"] is False
    assert (await me.get(f"{AUTH}/session")).status_code == 401
    again = await me.client.post(
        f"{AUTH}/login", json={"username": operator.username, "password": operator.password}
    )
    assert again.status_code == 401


async def test_password_reset(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    operator = await make_admin_with(settings, clock, ["admin:users:read"])
    me = await browsers(operator)

    reset = await boss.send("POST", f"{ADMIN}/users/{operator.id}/reset-password")
    assert reset.status_code == 200
    temporary = reset.json()["initial_password"]
    assert (await me.get(f"{AUTH}/session")).status_code == 401
    done = await me.client.post(
        f"{AUTH}/login", json={"username": operator.username, "password": temporary}
    )
    assert done.json()["pending"] == ["password_change"]


async def test_unlock_from_the_admin_api(
    app: FastAPI, browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    operator = await create_admin(settings, clock)
    async with extra_client(app, client_ip="10.7.7.7") as guesser:
        for _ in range(5):
            await guesser.post(
                f"{AUTH}/login", json={"username": operator.username, "password": random_password()}
            )
        locked = await guesser.post(
            f"{AUTH}/login", json={"username": operator.username, "password": operator.password}
        )
        assert locked.status_code == 429
        assert (await boss.send("POST", f"{ADMIN}/users/{operator.id}/unlock")).status_code == 204
        unlocked = await guesser.post(
            f"{AUTH}/login", json={"username": operator.username, "password": operator.password}
        )
        assert unlocked.status_code == 200


async def test_oneid_link_needs_a_pinfl(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    missing = await boss.send(
        "POST", f"{ADMIN}/users", {"username": "citizen", "auth_methods": ["oneid"]}
    )
    assert missing.status_code == 422
    created = await boss.send(
        "POST",
        f"{ADMIN}/users",
        {"username": "citizen", "auth_methods": ["oneid"], "pinfl": "31201234560045"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["pinfl_masked"] == "3120*****0045"
    assert body["initial_password"] is None  # OneID only: no password
    assert "31201234560045" not in created.text
    duplicate = await boss.send(
        "POST",
        f"{ADMIN}/users",
        {"username": "citizen2", "auth_methods": ["oneid"], "pinfl": "31201234560045"},
    )
    assert duplicate.status_code == 409


async def test_me(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    superadmin = await make_superadmin(settings, clock)
    me = await browsers(superadmin)
    body = (await me.get("/api/v1/me")).json()
    assert body["id"] == str(superadmin.id)
    assert body["username"] == superadmin.username
    assert body["permissions"] == ["*:*:*"]
    assert [r["name"] for r in body["roles"]] == ["superadmin"]
    assert "scopes" not in body
    assert "totp_enabled" not in body
    assert uuid.UUID(body["id"])


async def test_editing_an_admin(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    created = await boss.send(
        "POST",
        f"{ADMIN}/users",
        {"username": "citizen_only", "auth_methods": ["oneid"], "pinfl": "31201234560045"},
    )
    user_id = created.json()["id"]

    # Adding the password method creates a one-time temporary password.
    both = await boss.send(
        "PATCH", f"{ADMIN}/users/{user_id}", {"auth_methods": ["oneid", "password"]}
    )
    assert both.status_code == 200
    assert both.json()["initial_password"]
    assert both.json()["must_change_password"] is True

    relinked = await boss.send("PATCH", f"{ADMIN}/users/{user_id}", {"pinfl": "41201234560099"})
    assert relinked.json()["pinfl_masked"] == "4120*****0099"
    # OneID without a PINFL is refused; dropping OneID first makes unlinking possible.
    assert (
        await boss.send("PATCH", f"{ADMIN}/users/{user_id}", {"pinfl": None})
    ).status_code == 422
    only_password = await boss.send(
        "PATCH", f"{ADMIN}/users/{user_id}", {"auth_methods": ["password"], "pinfl": None}
    )
    assert only_password.status_code == 200
    assert only_password.json()["pinfl_masked"] is None

    assert (await boss.get(f"{ADMIN}/users/{user_id}")).json()["username"] == "citizen_only"
    assert (await boss.get(f"{ADMIN}/users/{uuid.uuid4()}")).status_code == 404


async def test_role_rename_and_lookup(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    first = (await boss.send("POST", f"{ADMIN}/roles", {"name": "first", "permissions": []})).json()
    await boss.send("POST", f"{ADMIN}/roles", {"name": "second", "permissions": []})
    clash = await boss.send("PATCH", f"{ADMIN}/roles/{first['id']}", {"name": "second"})
    assert clash.status_code == 409
    renamed = await boss.send(
        "PATCH", f"{ADMIN}/roles/{first['id']}", {"name": "renamed", "description": "yangi"}
    )
    assert renamed.json()["name"] == "renamed"
    assert renamed.json()["description"] == "yangi"
    duplicate = await boss.send("POST", f"{ADMIN}/roles", {"name": "renamed", "permissions": []})
    assert duplicate.status_code == 409
    assert (
        await boss.send("PATCH", f"{ADMIN}/roles/{uuid.uuid4()}", {"name": "zz"})
    ).status_code == 404
    unknown_role = await boss.send(
        "PUT", f"{ADMIN}/users/{uuid.uuid4()}/roles", {"role_ids": [first["id"]]}
    )
    assert unknown_role.status_code == 404
