"""Regions and organizations over /api/v1/admin, and a user's place in them."""

from typing import Any

from app.settings import Settings
from tests.conftest import AuditRecorder, FakeClock
from tests.helpers.rbac import make_admin_with, make_superadmin

ADMIN = "/api/v1/admin"


async def _region(boss: Any, name: str, **extra: Any) -> dict[str, Any]:
    response = await boss.send("POST", f"{ADMIN}/regions", {"name": name, **extra})
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def _organization(boss: Any, name: str, region_id: int, **extra: Any) -> dict[str, Any]:
    response = await boss.send(
        "POST", f"{ADMIN}/organizations", {"name": name, "region_id": region_id, **extra}
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _codes(response: Any) -> list[str]:
    return [f["type"] for f in response.json()["error"]["details"]["fields"]]


def _state(value: object) -> dict[str, Any]:
    """An audit event's `before` or `after`."""
    assert isinstance(value, dict)
    return value


async def test_regions_are_managed_and_audited(
    browsers: Any, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    region = await _region(boss, " Toshkent shahri ", dtm_id=26, p_code="26")
    assert region["name"] == "Toshkent shahri"
    assert (region["dtm_id"], region["p_code"], region["status"]) == (26, "26", True)
    assert isinstance(region["id"], int)

    taken = await boss.send("POST", f"{ADMIN}/regions", {"name": "Toshkent shahri"})
    assert taken.status_code == 409
    same_dtm = await boss.send("POST", f"{ADMIN}/regions", {"name": "Boshqa", "dtm_id": 26})
    assert same_dtm.status_code == 409

    await _region(boss, "Samarqand viloyati")
    found = (await boss.get(f"{ADMIN}/regions", params={"q": "toshkent"})).json()
    assert [r["name"] for r in found["items"]] == ["Toshkent shahri"]
    assert found["total"] == 1

    path = f"{ADMIN}/regions/{region['id']}"
    changed = await boss.send("PATCH", path, {"status": False, "p_code": None})
    assert changed.status_code == 200, changed.text
    assert (changed.json()["status"], changed.json()["p_code"]) == (False, None)
    inactive = (await boss.get(f"{ADMIN}/regions", params={"status": "false"})).json()
    assert [r["id"] for r in inactive["items"]] == [region["id"]]
    no_name = await boss.send("PATCH", path, {"name": None})
    assert no_name.status_code == 422
    assert _codes(no_name) == ["null_not_allowed"]

    assert (await boss.send("DELETE", path)).status_code == 204
    assert (await boss.get(path)).status_code == 404

    update = audit.find("admin.region.update")[-1]
    assert update.resource == "regions"
    assert update.resource_id == str(region["id"])
    assert update.before == {
        "name": "Toshkent shahri",
        "dtm_id": 26,
        "p_code": "26",
        "status": True,
    }
    assert update.after == {
        "name": "Toshkent shahri",
        "dtm_id": 26,
        "p_code": None,
        "status": False,
    }
    assert _state(audit.find("admin.region.delete")[-1].before)["name"] == "Toshkent shahri"


async def test_organizations_need_an_active_region(
    browsers: Any, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    region = await _region(boss, "Buxoro viloyati")
    other = await _region(boss, "Navoiy viloyati")
    closed = await _region(boss, "Yopiq hudud", status=False)

    org = await _organization(boss, "1-son test markazi", region["id"])
    assert (org["region_id"], org["status"]) == (region["id"], True)
    # The same name in another region is another organization.
    await _organization(boss, "1-son test markazi", other["id"])
    twice = await boss.send(
        "POST", f"{ADMIN}/organizations", {"name": "1-son test markazi", "region_id": region["id"]}
    )
    assert twice.status_code == 409

    for region_id in (closed["id"], 999_999):
        refused = await boss.send(
            "POST", f"{ADMIN}/organizations", {"name": "Yangi", "region_id": region_id}
        )
        assert refused.status_code == 422
        assert _codes(refused) == ["unknown_region"]

    listed = await boss.get(f"{ADMIN}/organizations", params={"region_id": other["id"]})
    assert [o["region_id"] for o in listed.json()["items"]] == [other["id"]]

    moved = await boss.send(
        "PATCH", f"{ADMIN}/organizations/{org['id']}", {"region_id": closed["id"]}
    )
    assert moved.status_code == 422
    renamed = await boss.send("PATCH", f"{ADMIN}/organizations/{org['id']}", {"name": "Markaz"})
    assert renamed.json()["name"] == "Markaz"
    before = _state(audit.find("admin.organization.update")[-1].before)
    assert before["name"] == "1-son test markazi"


async def test_nothing_in_use_can_be_deleted(
    browsers: Any, settings: Settings, clock: FakeClock
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    region = await _region(boss, "Xorazm viloyati")
    org = await _organization(boss, "Urganch markazi", region["id"])
    assert (await boss.send("DELETE", f"{ADMIN}/regions/{region['id']}")).status_code == 409

    user = await boss.send(
        "POST", f"{ADMIN}/users", {"username": "urganch_operator", "org_id": org["id"]}
    )
    assert user.status_code == 201, user.text
    blocked = await boss.send("DELETE", f"{ADMIN}/organizations/{org['id']}")
    assert blocked.status_code == 409
    assert "nofaol" in blocked.json()["error"]["message"]


async def test_permissions(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    reader = await browsers(await make_admin_with(settings, clock, ["admin:regions:read"]))
    assert (await reader.get(f"{ADMIN}/regions")).status_code == 200
    assert (await reader.send("POST", f"{ADMIN}/regions", {"name": "X hudud"})).status_code == 403
    assert (await reader.get(f"{ADMIN}/organizations")).status_code == 403
    unknown = await reader.get(f"{ADMIN}/regions", params={"sort": "name"})
    assert unknown.status_code == 422


async def test_a_user_belongs_to_an_organization_and_its_region(
    browsers: Any, settings: Settings, clock: FakeClock, audit: AuditRecorder
) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    region = await _region(boss, "Qashqadaryo viloyati")
    other = await _region(boss, "Surxondaryo viloyati")
    org = await _organization(boss, "Qarshi markazi", region["id"])
    far = await _organization(boss, "Termiz markazi", other["id"])
    closed = await _organization(boss, "Yopiq markaz", region["id"], status=False)

    # Only the organization: the region is the organization's.
    created = await boss.send(
        "POST", f"{ADMIN}/users", {"username": "qarshi_operator", "org_id": org["id"]}
    )
    assert created.status_code == 201, created.text
    user = created.json()
    assert (user["org_id"], user["region_id"]) == (org["id"], region["id"])
    assert _state(audit.find("admin.user.create")[-1].after)["region_id"] == region["id"]

    mismatch = await boss.send(
        "POST",
        f"{ADMIN}/users",
        {"username": "wrong_place", "org_id": org["id"], "region_id": other["id"]},
    )
    assert _codes(mismatch) == ["region_mismatch"]
    inactive = await boss.send(
        "POST", f"{ADMIN}/users", {"username": "closed_place", "org_id": closed["id"]}
    )
    assert _codes(inactive) == ["unknown_organization"]
    region_only = await boss.send(
        "POST", f"{ADMIN}/users", {"username": "region_only", "region_id": other["id"]}
    )
    assert (region_only.json()["org_id"], region_only.json()["region_id"]) == (None, other["id"])

    path = f"{ADMIN}/users/{user['id']}"
    # A new organization brings its region.
    moved = await boss.send("PATCH", path, {"org_id": far["id"]})
    assert moved.status_code == 200, moved.text
    assert (moved.json()["org_id"], moved.json()["region_id"]) == (far["id"], other["id"])
    update = audit.find("admin.user.update")[-1]
    assert (_state(update.before)["org_id"], _state(update.after)["org_id"]) == (
        org["id"],
        far["id"],
    )
    # No organization any more: the region stays.
    left = await boss.send("PATCH", path, {"org_id": None})
    assert (left.json()["org_id"], left.json()["region_id"]) == (None, other["id"])

    listed = await boss.get(f"{ADMIN}/users", params={"region_id": other["id"]})
    assert {u["username"] for u in listed.json()["items"]} == {"qarshi_operator", "region_only"}
    by_org = await boss.get(f"{ADMIN}/users", params={"org_id": far["id"]})
    assert by_org.json()["total"] == 0


async def test_me_shows_the_place(browsers: Any, settings: Settings, clock: FakeClock) -> None:
    boss = await browsers(await make_superadmin(settings, clock))
    me = (await boss.get("/api/v1/me")).json()
    assert (me["org_id"], me["region_id"]) == (None, None)
