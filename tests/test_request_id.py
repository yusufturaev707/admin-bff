import io
import json
import uuid

import httpx
import pytest

from app.core.logging import configure_logging
from app.core.request_id import parse_request_id
from app.settings import Settings


async def test_request_id_is_generated(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert uuid.UUID(response.headers["X-Request-ID"]).version == 4


async def test_valid_request_id_is_echoed_in_canonical_form(client: httpx.AsyncClient) -> None:
    incoming = uuid.uuid4()
    response = await client.get("/health", headers={"X-Request-ID": str(incoming).upper()})
    assert response.headers["X-Request-ID"] == str(incoming)


@pytest.mark.parametrize(
    "incoming",
    ["abc", "1; DROP TABLE x", "x" * 500, "0b9c5e1e-3f7a-4d43-9a43-6f1a2b9d8c1"],
)
async def test_invalid_request_id_is_replaced(client: httpx.AsyncClient, incoming: str) -> None:
    response = await client.get("/health", headers={"X-Request-ID": incoming})
    returned = response.headers["X-Request-ID"]
    assert returned != incoming
    uuid.UUID(returned)


def test_parse_request_id() -> None:
    value = uuid.uuid4()
    assert parse_request_id(str(value)) == str(value)
    assert parse_request_id(None) is None
    assert parse_request_id("") is None


async def test_access_log(settings: Settings, client: httpx.AsyncClient) -> None:
    stream = io.StringIO()
    configure_logging(settings, stream=stream)

    await client.get("/health")
    response = await client.get("/api/v1/missing", params={"pinfl": "31201234560045"})

    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    access = [r for r in records if r.get("logger") == "app.access"]
    assert len(access) == 1  # /health is not logged
    [record] = access
    assert record["event"] == "request"
    assert record["method"] == "GET"
    assert record["path"] == "/api/v1/missing"  # no query string
    assert record["status"] == 404
    assert record["request_id"] == response.headers["X-Request-ID"]
    assert isinstance(record["duration_ms"], float | int)
    assert "31201234560045" not in stream.getvalue()
