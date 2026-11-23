"""The audit tables in PostgreSQL (section 9): append-only, partitions, retention,
and tamper detection by the hash chain."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import timedelta

import asyncpg
import pytest

from app.audit.chain import GENESIS_HASH, AuditRow
from app.audit.models import AUDIT_CHAIN_LOCK_KEY
from app.audit.verify import apply_retention, verify_chain
from app.audit.writer import DbAuditSink
from app.core.time import utcnow
from app.settings import Settings
from tests.audit_helpers import event, month_partition, records, sessions, write_events
from tests.conftest import FakeClock, Services


@pytest.fixture
async def pg(services: Services) -> AsyncIterator[asyncpg.Connection]:
    """A connection as the owner of the test database (the migration role).
    These tests count records: they start from an empty audit log."""
    await services.reset()
    conn = await services.pg_connect()
    try:
        yield conn
    finally:
        await conn.close()
        await services.reset()


async def _partitions(pg: asyncpg.Connection) -> list[str]:
    rows = await pg.fetch(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
        "WHERE i.inhparent = 'audit_log'::regclass ORDER BY 1"
    )
    return [r["relname"] for r in rows]


# --- append-only ---------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET actor_username = 'x'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        "UPDATE {partition} SET actor_username = 'x'",
        "DELETE FROM {partition}",
        "TRUNCATE {partition}",
        "UPDATE audit_anchors SET rows_dropped = 0",
        "DELETE FROM audit_anchors",
        "TRUNCATE audit_anchors",
    ],
)
async def test_audit_tables_are_append_only_even_for_the_owner(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock, statement: str
) -> None:
    await write_events(settings, clock, 2)
    await pg.execute(
        "INSERT INTO audit_anchors (partition_name, rows_dropped, last_id, last_ts, last_hash) "
        "VALUES ('audit_log_y2000m01', 1, 0, now(), $1)",
        GENESIS_HASH,
    )
    sql = statement.format(partition=month_partition(clock()))
    with pytest.raises(asyncpg.InsufficientPrivilegeError, match="append-only"):
        await pg.execute(sql)
    assert len(await records(settings)) == 2


# --- partitions ------------------------------------------------------------------


async def test_partition_is_chosen_by_the_utc_month(pg: asyncpg.Connection) -> None:
    # The last half hour of a UTC month is already the next month in Tashkent.
    month_start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    ts = month_start - timedelta(minutes=30)
    start = (ts - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    name = await pg.fetchval("SELECT audit_ensure_partition($1)", ts)
    assert name == month_partition(ts) == month_partition(start)
    assert await pg.fetchval("SELECT audit_ensure_partition($1)", ts) == name  # idempotent
    await pg.execute("SET TimeZone = 'UTC'")
    bound = await pg.fetchval(
        "SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = $1", name
    )
    assert bound == (
        f"FOR VALUES FROM ('{start:%Y-%m-%d} 00:00:00+00') "
        f"TO ('{month_start:%Y-%m-%d} 00:00:00+00')"
    )
    trigger = await pg.fetchval(
        "SELECT tgname FROM pg_trigger WHERE tgrelid = $1::regclass AND tgname = "
        "'audit_log_no_truncate'",
        name,
    )
    assert trigger == "audit_log_no_truncate"


@pytest.mark.parametrize("offset_days", [-500, 500])
async def test_partitions_only_near_the_present(pg: asyncpg.Connection, offset_days: int) -> None:
    with pytest.raises(asyncpg.RaiseError, match="out of the allowed range"):
        await pg.execute(
            "SELECT audit_ensure_partition($1)", utcnow() + timedelta(days=offset_days)
        )
    with pytest.raises(asyncpg.RaiseError, match="out of the allowed range"):
        await pg.execute("SELECT audit_ensure_partition(NULL)")


async def test_functions_use_the_chain_lock_key(pg: asyncpg.Connection) -> None:
    for name in ("audit_ensure_partition", "audit_drop_expired_partitions"):
        source = await pg.fetchval(
            "SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname = $1", name
        )
        assert f"pg_advisory_xact_lock({AUDIT_CHAIN_LOCK_KEY})" in source
        assert "SECURITY DEFINER" in source
        assert "search_path TO 'pg_catalog', 'pg_temp'" in source


async def test_functions_are_not_executable_by_public(pg: asyncpg.Connection) -> None:
    rows = await pg.fetch(
        "SELECT proname, has_function_privilege('public', oid, 'EXECUTE') AS public_exec "
        "FROM pg_proc WHERE proname LIKE 'audit\\_%'"
    )
    assert {r["proname"] for r in rows} == {
        "audit_reject_change",
        "audit_ensure_partition",
        "audit_drop_expired_partitions",
    }
    assert not any(r["public_exec"] for r in rows)


# --- retention -------------------------------------------------------------------


@pytest.mark.parametrize("days", [None, 0, 30, 89])
async def test_retention_is_at_least_90_days(pg: asyncpg.Connection, days: int | None) -> None:
    with pytest.raises(asyncpg.RaiseError, match="at least 90 days"):
        await pg.fetch("SELECT * FROM audit_drop_expired_partitions($1)", days)


async def test_retention_anchors_and_drops_old_partitions(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    now = clock()
    clock.now = now - timedelta(days=200)
    await write_events(settings, clock, 3)
    old = await records(settings)
    clock.now = now - timedelta(days=60)  # newer than 90 days: kept
    await write_events(settings, clock, 1)
    clock.now = now
    await write_events(settings, clock, 2)

    async with sessions(settings) as db:
        dropped = await apply_retention(db, retention_days=90)
        assert [(d.name, d.rows, d.last_id) for d in dropped] == [
            (month_partition(old[0].ts), 3, old[-1].id)
        ]
        assert dropped[0].last_hash == old[-1].hash
        anchor = await pg.fetchrow("SELECT * FROM audit_anchors")
        assert (anchor["last_id"], anchor["last_hash"]) == (old[-1].id, old[-1].hash)
        assert month_partition(old[0].ts) not in await _partitions(pg)
        # Next month's partition is created ahead of time.
        assert month_partition(utcnow() + timedelta(days=31)) in await _partitions(pg)

        result = await verify_chain(db)
        assert result.ok, result.problems
        assert (result.anchor_id, result.checked) == (anchor["id"], 3)
        assert result.first_id == old[-1].id + 1

        assert await apply_retention(db, retention_days=90) == []  # nothing more to drop


async def test_chain_continues_from_the_anchor_when_everything_was_dropped(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    now = clock()
    clock.now = now - timedelta(days=200)
    await write_events(settings, clock, 2)
    old = await records(settings)
    async with sessions(settings) as db:
        await apply_retention(db, retention_days=90)
        assert await records(settings) == []
        clock.now = now - timedelta(days=300)  # a clock far behind the anchor
        await DbAuditSink(db, clock=clock).write(event())
        [new] = await records(settings)
        assert new.prev_hash == old[-1].hash
        assert new.ts == old[-1].ts  # time does not go backwards along the chain
        assert (await verify_chain(db)).ok


# --- tamper detection --------------------------------------------------------------


async def _tamper(pg: asyncpg.Connection, partition: str, sql: str, *args: object) -> None:
    """What only the owner can do: switch the trigger off, change, switch it on."""
    await pg.execute(f"ALTER TABLE {partition} DISABLE TRIGGER audit_log_append_only")
    try:
        await pg.execute(sql, *args)
    finally:
        await pg.execute(f"ALTER TABLE {partition} ENABLE TRIGGER audit_log_append_only")


async def _problems(settings: Settings) -> list[tuple[int, str]]:
    async with sessions(settings) as db:
        result = await verify_chain(db)
    return [(p.record_id, p.kind) for p in result.problems]


async def test_verify_accepts_an_intact_chain(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    async with sessions(settings) as db:
        empty = await verify_chain(db)
        assert empty.ok
        assert (empty.checked, empty.first_id, empty.last_id) == (0, None, None)
    await write_events(settings, clock, 3)
    rows = await records(settings)
    assert rows[0].prev_hash == GENESIS_HASH
    assert [r.prev_hash for r in rows[1:]] == [r.hash for r in rows[:-1]]
    async with sessions(settings) as db:
        result = await verify_chain(db)
    assert result.ok
    assert (result.checked, result.first_id, result.last_id) == (3, rows[0].id, rows[-1].id)
    assert result.last_hash == rows[-1].hash


async def test_verify_finds_a_modified_record(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 3)
    rows = await records(settings)
    await _tamper(
        pg,
        month_partition(rows[1].ts),
        "UPDATE audit_log SET outcome = 'denied' WHERE id = $1",
        rows[1].id,
    )
    assert await _problems(settings) == [(rows[1].id, "hash")]


async def test_verify_finds_a_deleted_record(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 3)
    rows = await records(settings)
    await _tamper(
        pg, month_partition(rows[1].ts), "DELETE FROM audit_log WHERE id = $1", rows[1].id
    )
    assert await _problems(settings) == [(rows[2].id, "prev_hash")]


async def test_verify_finds_a_deleted_first_record(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 2)
    rows = await records(settings)
    await _tamper(
        pg, month_partition(rows[0].ts), "DELETE FROM audit_log WHERE id = $1", rows[0].id
    )
    assert await _problems(settings) == [(rows[1].id, "prev_hash")]


async def _insert(pg: asyncpg.Connection, row: AuditRow, prev_hash: str, digest: str) -> int:
    """A record inserted by hand, bypassing the writer."""
    columns = {**row.columns(), "prev_hash": prev_hash, "hash": digest}
    for name in ("before", "after", "details"):  # asyncpg passes jsonb as text
        columns[name] = None if columns[name] is None else json.dumps(columns[name])
    placeholders = ", ".join(f"${i}" for i in range(1, len(columns) + 1))
    # Column names are the model's own, values are bound parameters.
    sql = f"INSERT INTO audit_log ({', '.join(columns)}) VALUES ({placeholders}) RETURNING id"  # noqa: S608
    record_id: int = await pg.fetchval(sql, *columns.values())
    return record_id


async def test_verify_finds_a_forged_record(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    """Someone with the application's credentials appends a record by hand."""
    await write_events(settings, clock, 2)
    last = (await records(settings))[-1]
    row = AuditRow.from_event(event(), clock())
    forged = await _insert(pg, row, last.hash, "f" * 64)
    assert await _problems(settings) == [(forged, "hash")]


async def test_verify_finds_a_backdated_record(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 2)
    last = (await records(settings))[-1]
    row = AuditRow.from_event(event(), last.ts - timedelta(minutes=5))
    backdated = await _insert(pg, row, last.hash, row.chain_hash(last.hash))
    assert await _problems(settings) == [(backdated, "ts")]


async def test_verify_finds_a_duplicate_id(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 2)
    rows = await records(settings)
    row = AuditRow.from_event(event(), rows[-1].ts + timedelta(seconds=1))
    await pg.execute(
        f"ALTER SEQUENCE audit_log_id_seq RESTART WITH {rows[-1].id}"  # reuse the last id
    )
    duplicate = await _insert(pg, row, rows[-1].hash, row.chain_hash(rows[-1].hash))
    assert duplicate == rows[-1].id
    assert await _problems(settings) == [(duplicate, "duplicate_id")]


async def test_verify_finds_a_record_older_than_the_anchor(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    now = clock()
    clock.now = now - timedelta(days=200)
    await write_events(settings, clock, 2)
    old = await records(settings)
    clock.now = now
    await write_events(settings, clock, 1)
    async with sessions(settings) as db:
        await apply_retention(db, retention_days=90)
    # A record with an id from the dropped part reappears.
    row = AuditRow.from_event(event(), clock())
    await pg.execute(f"ALTER SEQUENCE audit_log_id_seq RESTART WITH {old[0].id}")
    stale = await _insert(pg, row, GENESIS_HASH, row.chain_hash(GENESIS_HASH))
    assert (stale, "prev_hash") in await _problems(settings)


async def test_writer_holds_the_chain_lock(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    """While another transaction holds the lock, an append waits for it."""
    await pg.execute("BEGIN")
    await pg.execute("SELECT pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_KEY)
    async with sessions(settings) as db:
        task = asyncio.create_task(DbAuditSink(db, clock=clock).write(event()))
        await asyncio.sleep(0.3)
        assert not task.done()
        await pg.execute("COMMIT")
        await asyncio.wait_for(task, 5)
    assert len(await records(settings)) == 1
