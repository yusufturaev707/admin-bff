"""scripts/verify_audit.py: the audit log check run on the server (section 9)."""

import asyncio
import secrets
from collections.abc import AsyncIterator

import asyncpg
import pytest

from app.audit.verify import VerifyResult
from app.settings import Settings
from scripts import verify_audit as script
from tests.conftest import FakeClock, Services
from tests.helpers.audit import month_partition, records, write_events


@pytest.fixture
async def pg(services: Services) -> AsyncIterator[asyncpg.Connection]:
    """The owner of the test database; the tests start from an empty audit log."""
    await services.reset()
    conn = await services.pg_connect()
    try:
        yield conn
    finally:
        await conn.close()
        await services.reset()


def _problems(result: VerifyResult) -> list[tuple[int, str]]:
    return [(p.record_id, p.kind) for p in result.problems]


async def test_journald_shows_records_cut_off_the_end(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 3)
    last = (await records(settings))[-1]
    journal = (last.id, last.hash)
    assert (await script.verify(settings, journal)).ok

    # What only the owner can do: switch the trigger off and delete the newest record.
    partition = month_partition(last.ts)
    await pg.execute(f"ALTER TABLE {partition} DISABLE TRIGGER audit_log_append_only")
    try:
        await pg.execute("DELETE FROM audit_log WHERE id = $1", last.id)
    finally:
        await pg.execute(f"ALTER TABLE {partition} ENABLE TRIGGER audit_log_append_only")

    # The chain alone cannot see it: the records left are still linked.
    assert (await script.verify(settings)).ok
    assert _problems(await script.verify(settings, journal)) == [(last.id, "missing")]


async def test_a_copy_with_another_hash_is_reported(
    pg: asyncpg.Connection, settings: Settings, clock: FakeClock
) -> None:
    await write_events(settings, clock, 1)
    [only] = await records(settings)
    result = await script.verify(settings, (only.id, "0" * 64))
    assert _problems(result) == [(only.id, "hash")]


def test_main_prints_the_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings: Settings,
    services: Services,
    clock: FakeClock,
) -> None:
    monkeypatch.setattr(script, "load_settings", lambda: settings)
    asyncio.run(services.reset())
    try:
        asyncio.run(write_events(settings, clock, 2))
        last = asyncio.run(records(settings))[-1]

        assert script.main([]) == 0
        out = capsys.readouterr().out
        assert "Tekshirilgan yozuvlar: 2" in out
        assert "muammo topilmadi" in out
        assert "journald bilan solishtirilmadi" in out

        newer = ["--journal-id", str(last.id + 1), "--journal-hash", last.hash]
        assert script.main(newer) == 1
        out = capsys.readouterr().out
        assert "MUAMMO TOPILDI" in out
        assert "bazada yo'q" in out

        with pytest.raises(SystemExit) as exited:
            script.main(["--journal-id", "1"])  # without its hash
        assert exited.value.code == 2

        missing = settings.model_copy(update={"db_name": f"missing_{secrets.token_hex(4)}"})
        monkeypatch.setattr(script, "load_settings", lambda: missing)
        assert script.main([]) == 1
        assert "Bazaga ulanib bo'lmadi" in capsys.readouterr().err
    finally:
        asyncio.run(services.reset())
