"""POST /api/v1/audit/export: CSV, rate limit, audited (sections 9 and 11)."""

import csv
import io
import secrets

import httpx
import pytest

from app.audit import service as audit_service
from app.audit.service import EXPORTS_PER_HOUR, csv_cell
from app.core.ratelimit import FixedWindowLimiter
from app.settings import Settings
from tests.audit_helpers import records, write_events
from tests.auth_helpers import login
from tests.conftest import FakeClock, Services
from tests.rbac_helpers import make_admin_with

EXPORT = "/api/v1/audit/export"


async def _exporter(client: httpx.AsyncClient, settings: Settings, clock: FakeClock) -> str:
    admin = await make_admin_with(settings, clock, ["audit:logs:export"])
    return await login(client, admin, clock)


def _rows(response: httpx.Response) -> list[list[str]]:
    text = response.content.decode("utf-8")
    assert text.startswith("﻿")  # BOM: Excel reads the file as UTF-8
    return list(csv.reader(io.StringIO(text[1:])))


async def test_export_is_a_csv_of_the_filtered_log(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    csrf = await _exporter(client, settings, clock)
    await write_events(
        settings,
        clock,
        3,
        action="test.csv.row",
        user_agent='=HYPERLINK("http://evil")',
        details={"note": "+cmd", "n": 1},
    )
    response = await client.post(
        EXPORT, json={"action": "test.csv.row"}, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith('attachment; filename="audit-')
    header, *rows = _rows(response)
    assert header[:3] == ["id", "ts", "actor_id"]
    assert len(rows) == 3
    stored = await records(settings, action="test.csv.row")
    assert [row[0] for row in rows] == [str(r.id) for r in stored]  # oldest first
    column = dict(zip(header, rows[0], strict=True))
    assert column["user_agent"] == '\'=HYPERLINK("http://evil")'  # no formula
    assert column["details"] == '{"n": 1, "note": "+cmd"}'
    assert column["ts"].endswith("Z")
    assert column["status_code"] == ""


async def test_export_is_audited(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    csrf = await _exporter(client, settings, clock)
    await write_events(settings, clock, 2, action="test.csv.audited")
    body = {"action": "test.csv.audited", "from": "2026-01-01T00:00:00Z"}
    response = await client.post(EXPORT, json=body, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    [record] = await records(settings, request_id=response.headers["X-Request-ID"])
    assert (record.action, record.system_id, record.resource) == (
        "audit.logs.export",
        "audit",
        "logs",
    )
    assert record.details == {
        "filters": {"action": "test.csv.audited", "since": "2026-01-01T00:00:00Z"},
        "rows": 2,
        "format": "csv",
    }


async def test_export_needs_its_permission_and_the_csrf_token(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    reader = await make_admin_with(settings, clock, ["audit:logs:read"])
    csrf = await login(client, reader, clock)
    response = await client.post(EXPORT, json={}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"

    await _exporter(client, settings, clock)
    response = await client.post(EXPORT, json={})  # no CSRF token
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_export_is_limited_per_hour(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock
) -> None:
    csrf = await _exporter(client, settings, clock)
    for _ in range(EXPORTS_PER_HOUR):
        response = await client.post(EXPORT, json={}, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
    response = await client.post(EXPORT, json={}, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert 0 < int(response.headers["Retry-After"]) <= 3600
    assert len(await records(settings, action="audit.logs.export")) == EXPORTS_PER_HOUR


async def test_too_many_rows_is_refused_without_using_up_the_limit(
    client: httpx.AsyncClient,
    settings: Settings,
    clock: FakeClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf = await _exporter(client, settings, clock)
    monkeypatch.setattr(audit_service, "MAX_EXPORT_ROWS", 1)
    await write_events(settings, clock, 2, action="test.csv.many")
    for _ in range(EXPORTS_PER_HOUR + 1):
        response = await client.post(
            EXPORT, json={"action": "test.csv.many"}, headers={"X-CSRF-Token": csrf}
        )
        assert response.status_code == 422
        assert response.json()["error"]["details"]["fields"][0]["type"] == "too_many_rows"
    response = await client.post(
        EXPORT, json={"action": "test.nothing"}, headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"nope": 1},
        {"from": "2026-11-23T10:00:00"},
        {"from": "2026-11-23T10:00:00Z", "to": "2026-11-22T10:00:00Z"},
        {"outcome": "maybe"},
        {"action": ""},
    ],
)
async def test_export_rejects_bad_filters(
    client: httpx.AsyncClient, settings: Settings, clock: FakeClock, body: dict[str, object]
) -> None:
    csrf = await _exporter(client, settings, clock)
    response = await client.post(EXPORT, json=body, headers={"X-CSRF-Token": csrf})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize(
    ("value", "cell"),
    [
        (None, ""),
        ("plain", "plain"),
        ("=1+1", "'=1+1"),
        ("+1", "'+1"),
        ("-1", "'-1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        (42, "42"),
        (["a"], '["a"]'),
    ],
)
def test_csv_cells_never_start_a_formula(value: object, cell: str) -> None:
    assert csv_cell(value) == cell


async def test_fixed_window_limiter(services: Services) -> None:
    redis = services.redis()
    try:
        limiter = FixedWindowLimiter(
            redis, prefix=services.redis_prefix, name="test", limit=2, window_s=60
        )
        subject = secrets.token_hex(4)
        assert await limiter.check(subject) is None
        assert await limiter.hit(subject) is None
        assert await limiter.hit(subject) is None
        retry_after = await limiter.check(subject)
        assert retry_after is not None
        assert 0 < retry_after <= 60
        over = await limiter.hit(subject)
        assert over is not None
        assert 0 < over <= 60
        assert await limiter.check(secrets.token_hex(4)) is None  # per subject
    finally:
        await redis.aclose()
        await services.reset()
