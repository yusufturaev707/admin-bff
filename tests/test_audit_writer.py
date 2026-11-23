"""DbAuditSink: appends to the chain and copies every event to the log (section 9)."""

import asyncio
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy.exc import DBAPIError

from app.audit.chain import GENESIS_HASH
from app.audit.context import end_request, start_request
from app.audit.sink import AuditEvent, AuditOutcome, LogAuditSink
from app.audit.verify import verify_chain
from app.audit.writer import DbAuditSink
from app.core.db import database_url
from app.core.logging import configure_logging
from app.settings import Settings
from tests.audit_helpers import event, records, sessions
from tests.conftest import AuditRecorder, FakeClock, Services


@pytest.fixture
async def clean(services: Services) -> AsyncIterator[None]:
    """These tests count records: they start from an empty audit log."""
    await services.reset()
    yield
    await services.reset()


@pytest.fixture
def log_stream(settings: Settings) -> io.StringIO:
    stream = io.StringIO()
    configure_logging(settings, stream=stream)
    return stream


def _audit_lines(stream: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    return [line for line in lines if line.get("logger") == "audit"]


@pytest.mark.usefixtures("clean")
async def test_records_are_chained_in_order(settings: Settings, clock: FakeClock) -> None:
    async with sessions(settings) as db:
        sink = DbAuditSink(db, clock=clock)
        for _ in range(3):
            clock.advance(1)
            await sink.write(event())
    rows = await records(settings)
    assert [r.prev_hash for r in rows] == [GENESIS_HASH, rows[0].hash, rows[1].hash]
    assert [r.ts for r in rows] == sorted(r.ts for r in rows)
    assert rows[0].ts == clock.now - timedelta(seconds=2)


@pytest.mark.usefixtures("clean")
async def test_time_never_goes_backwards_along_the_chain(
    settings: Settings, clock: FakeClock
) -> None:
    async with sessions(settings) as db:
        sink = DbAuditSink(db, clock=clock)
        await sink.write(event())
        clock.advance(-3600)  # the clock jumps back an hour
        await sink.write(event())
    first, second = await records(settings)
    assert second.ts == first.ts


@pytest.mark.usefixtures("clean")
async def test_concurrent_appends_form_one_chain(settings: Settings, clock: FakeClock) -> None:
    engine_url = database_url(settings)
    async with sessions(settings, engine_url) as db:
        sinks = [DbAuditSink(db, clock=clock) for _ in range(5)]
        await asyncio.gather(*(sinks[i % 5].write(event()) for i in range(30)))
        result = await verify_chain(db)
    assert result.ok, result.problems
    assert result.checked == 30


@pytest.mark.usefixtures("clean")
async def test_awkward_values_survive_the_round_trip(settings: Settings, clock: FakeClock) -> None:
    """Whatever an event carries, the stored record still verifies."""
    awkward = AuditEvent(
        action="test.awkward.values",
        outcome=AuditOutcome.ERROR,
        actor_id=uuid.uuid4(),
        actor_username="o\x00perator",
        actor_ip="2001:0db8::0001",
        user_agent="Mozilla/5.0 \udcff \U0001f600 o\u02bbzbek",
        session_hash="cd" * 32,
        request_id="not-a-uuid",
        system_id="faceid",
        resource="students",
        resource_id="31201234560045",
        status_code=422,
        before={"nested": {"deep": [1, 2.5, None, True, {"x": 1e16}]}, "set": {"b", "a"}},
        after=["\x00", "", "'quoted' \"double\" \\ backslash"],
        reason="Sabab: \t tab va yangi\nqator",
        details={"path": "/api/v1/x\x00y", "when": clock(), "id": uuid.uuid4()},
    )
    async with sessions(settings) as db:
        await DbAuditSink(db, clock=clock).write(awkward)
        await DbAuditSink(db, clock=clock).write(event(actor_ip="unknown"))
        result = await verify_chain(db)
    assert result.ok, result.problems
    stored, unknown_ip = await records(settings)
    assert stored.actor_username == "operator"
    assert str(stored.actor_ip) == "2001:db8::1"
    assert stored.resource_id == "3120*****0045"
    assert stored.details["path"] == "/api/v1/xy"
    assert stored.before["nested"]["deep"][1] == "2.5"
    assert unknown_ip.actor_ip is None


@pytest.mark.usefixtures("clean")
async def test_every_record_is_copied_to_the_log_with_its_hash(
    settings: Settings, clock: FakeClock, log_stream: io.StringIO
) -> None:
    async with sessions(settings) as db:
        await DbAuditSink(db, clock=clock).write(
            event(details={"password": "hunter2-hunter2", "pinfl": "31201234560045"})
        )
    [record] = await records(settings)
    [line] = _audit_lines(log_stream)
    assert (line["audit_id"], line["hash"]) == (record.id, record.hash)
    assert line["action"] == record.action
    assert line["details"] == {"password": "[REDACTED]", "pinfl": "3120*****0045"}
    assert "hunter2" not in log_stream.getvalue()
    assert "31201234560045" not in log_stream.getvalue()


async def test_a_failed_write_is_logged_and_raised(
    settings: Settings, clock: FakeClock, log_stream: io.StringIO
) -> None:
    broken = database_url(settings).set(database=f"missing_{uuid.uuid4().hex}")
    state, token = start_request()
    try:
        async with sessions(settings, broken) as db:
            with pytest.raises(DBAPIError):
                await DbAuditSink(db, clock=clock).write(event(action="auth.login"))
        # No second (request-level) attempt for the same request.
        assert state.written
    finally:
        end_request(token)
    [line] = _audit_lines(log_stream)
    assert line["stored"] is False
    assert line["level"] == "error"
    assert line["action"] == "auth.login"
    assert "audit_id" not in line


@pytest.mark.usefixtures("clean")
async def test_listeners_get_events_and_cannot_break_a_write(
    settings: Settings, clock: FakeClock, log_stream: io.StringIO
) -> None:
    class Broken:
        async def write(self, event: AuditEvent) -> None:
            raise RuntimeError("listener bug")

    recorder = AuditRecorder()
    async with sessions(settings) as db:
        sink = DbAuditSink(db, clock=clock, listeners=[Broken(), recorder])
        await sink.write(event(action="test.listened.to"))
    assert [e.action for e in recorder.events] == ["test.listened.to"]
    assert len(await records(settings)) == 1
    assert "audit_listener_failed" in log_stream.getvalue()


async def test_log_sink_writes_events_on_its_own(log_stream: io.StringIO) -> None:
    await LogAuditSink().write(event(action="test.log.only", request_id="r-1"))
    [line] = _audit_lines(log_stream)
    assert (line["action"], line["audit_request_id"]) == ("test.log.only", "r-1")
    assert "hash" not in line
