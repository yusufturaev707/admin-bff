"""CLI: verify-audit, audit-retention, and CLI actions in the audit chain (section 9)."""

import asyncio
import getpass
from datetime import timedelta

import pytest

from app import cli
from app.settings import Settings
from tests.audit_helpers import month_partition, records, write_events
from tests.conftest import FakeClock, Services


@pytest.fixture(autouse=True)
def empty_audit_log(services: Services) -> None:
    """These tests count records: they start from an empty audit log."""
    asyncio.run(services.reset())


def test_verify_audit_on_an_intact_chain(
    cli_env: Settings, clock: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    asyncio.run(write_events(cli_env, clock, 3))
    assert cli.main(["verify-audit"]) == 0
    out = capsys.readouterr().out
    assert "Audit zanjiri butun: 3 ta yozuv tekshirildi (boshidan)." in out
    last = asyncio.run(records(cli_env))[2]
    assert f"id={last.id}, hash={last.hash}" in out

    [verified] = asyncio.run(records(cli_env, action="audit.chain.verify"))
    assert (verified.outcome, verified.actor_username) == ("success", "cli")
    assert verified.details["checked"] == 3
    assert verified.details["problems"] == []
    assert "os_user" in verified.details


def test_verify_audit_reports_a_broken_chain(
    cli_env: Settings,
    clock: FakeClock,
    services: Services,
    capsys: pytest.CaptureFixture[str],
) -> None:
    asyncio.run(write_events(cli_env, clock, 3))
    rows = asyncio.run(records(cli_env))
    partition = month_partition(rows[1].ts)

    async def tamper() -> None:
        conn = await services.pg_connect()
        try:
            await conn.execute(f"ALTER TABLE {partition} DISABLE TRIGGER audit_log_append_only")
            await conn.execute("DELETE FROM audit_log WHERE id = $1", rows[1].id)
            await conn.execute(f"ALTER TABLE {partition} ENABLE TRIGGER audit_log_append_only")
        finally:
            await conn.close()

    asyncio.run(tamper())
    assert cli.main(["verify-audit"]) == 1
    err = capsys.readouterr().err
    assert "XATO: audit zanjiri buzilgan" in err
    assert f"id={rows[2].id} [prev_hash]" in err
    [verified] = asyncio.run(records(cli_env, action="audit.chain.verify"))
    assert verified.outcome == "error"
    assert verified.details["problems"] == [{"id": rows[2].id, "kind": "prev_hash"}]


def test_audit_retention(
    cli_env: Settings, clock: FakeClock, capsys: pytest.CaptureFixture[str]
) -> None:
    now = clock()
    clock.now = now - timedelta(days=200)
    asyncio.run(write_events(cli_env, clock, 2))
    clock.now = now
    asyncio.run(write_events(cli_env, clock, 1))
    old_partition = month_partition(now - timedelta(days=200))

    assert cli.main(["audit-retention"]) == 0
    out = capsys.readouterr().out
    assert f"O'chirildi: {old_partition} (2 ta yozuv)" in out
    assert "Audit retention (90 kun): 1 ta partition o'chirildi." in out
    [dropped] = asyncio.run(records(cli_env, action="audit.partition.drop"))
    assert (dropped.resource, dropped.resource_id) == ("partitions", old_partition)
    assert dropped.details["rows"] == 2
    assert dropped.details["retention_days"] == 90

    assert cli.main(["audit-retention"]) == 0  # nothing left to drop
    assert "0 ta partition o'chirildi" in capsys.readouterr().out
    assert cli.main(["verify-audit"]) == 0
    assert "(anchor #" in capsys.readouterr().out


def test_cli_actions_are_audited_with_the_os_user(
    cli_env: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SUDO_USER", "operator_on_the_server")
    assert cli.main(["unlock-login", "--ip", "10.1.2.3"]) == 0
    [record] = asyncio.run(records(cli_env, action="auth.unlock"))
    assert record.actor_username == "cli"
    assert record.details["os_user"] == "operator_on_the_server"
    assert record.details["ip"] == "10.1.2.3"


def test_os_user_may_be_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUDO_USER", raising=False)

    def no_name() -> str:
        raise OSError("no name for the uid")

    monkeypatch.setattr(getpass, "getuser", no_name)
    assert cli._os_user() is None
