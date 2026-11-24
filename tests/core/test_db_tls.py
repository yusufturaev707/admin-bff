"""TLS to a database on another server (DB_SSLMODE, DB_SSLROOTCERT)."""

import ssl
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from structlog.testing import capture_logs

from app import main
from app.core import db
from app.settings import Settings, db_host_is_local


@pytest.mark.parametrize(
    ("host", "local"),
    [
        ("/var/run/postgresql", True),
        ("localhost", True),
        ("127.0.0.1", True),
        ("127.0.1.1", True),
        ("::1", True),
        ("10.20.30.40", False),
        ("db.uzbmb.uz", False),
        ("2001:db8::5", False),
    ],
)
def test_local_hosts(host: str, local: bool) -> None:
    assert db_host_is_local(host) is local


@pytest.mark.parametrize("host", ["10.20.30.40", "db.uzbmb.uz"])
def test_another_host_prefers_tls_by_default(clean_env: pytest.MonkeyPatch, host: str) -> None:
    # Owner's decision (2026-11-24): only host, port, name, user and password.
    settings = Settings(_env_file=None, db_host=host)
    assert settings.db_sslmode is None
    assert settings.db_tls_mode == "prefer"


@pytest.mark.parametrize("host", ["10.20.30.40", "db.uzbmb.uz"])
def test_production_refuses_to_switch_tls_off_to_another_host(
    clean_env: pytest.MonkeyPatch, host: str
) -> None:
    with pytest.raises(ValidationError, match="DB_SSLMODE=disable"):
        Settings(_env_file=None, db_host=host, db_sslmode="disable")


@pytest.mark.parametrize("host", ["/var/run/postgresql", "127.0.0.1", "localhost"])
def test_same_host_defaults_to_plain_text(clean_env: pytest.MonkeyPatch, host: str) -> None:
    assert Settings(_env_file=None, db_host=host).db_tls_mode == "disable"


def test_production_accepts_prefer_without_a_root_cert(clean_env: pytest.MonkeyPatch) -> None:
    settings = Settings(_env_file=None, db_host="10.20.30.40", db_sslmode="prefer")
    assert settings.db_tls_mode == "prefer"


@pytest.mark.parametrize("mode", ["verify-full", "verify-ca"])
def test_production_accepts_tls_to_another_host(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    ca = tmp_path / "db-ca.crt"
    ca.write_text("not parsed by the settings")
    settings = Settings(
        _env_file=None, db_host="10.20.30.40", db_sslmode=mode, db_sslrootcert=str(ca)
    )
    assert settings.db_tls_mode == mode


def test_development_allows_plain_text_to_another_host(clean_env: pytest.MonkeyPatch) -> None:
    Settings(
        _env_file=None,
        app_env="development",
        log_format="console",
        db_host="10.0.0.5",
        db_sslmode="disable",
    )


@pytest.mark.parametrize("mode", ["require", "allow"])
def test_other_libpq_modes_do_not_exist(clean_env: pytest.MonkeyPatch, mode: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", db_host="10.0.0.5", db_sslmode=mode)


@pytest.mark.parametrize("mode", ["prefer", "verify-full"])
def test_tls_on_a_unix_socket_is_refused(clean_env: pytest.MonkeyPatch, mode: str) -> None:
    # PostgreSQL never encrypts a unix socket: the setting would only look safe.
    with pytest.raises(ValidationError, match="unix socket"):
        Settings(_env_file=None, db_host="/var/run/postgresql", db_sslmode=mode)


@pytest.mark.parametrize(
    ("host", "mode"),
    [("127.0.0.1", None), ("10.0.0.5", None), ("10.0.0.5", "prefer")],
)
def test_root_cert_without_a_verifying_mode_is_refused(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, host: str, mode: str | None
) -> None:
    # "prefer" never checks the certificate: the CA file would only look used.
    ca = tmp_path / "db-ca.crt"
    ca.write_text("x")
    with pytest.raises(ValidationError, match="DB_SSLROOTCERT"):
        Settings(
            _env_file=None, app_env="test", db_host=host, db_sslmode=mode, db_sslrootcert=str(ca)
        )


def test_missing_root_cert_is_refused(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="no such file"):
        Settings(
            _env_file=None,
            db_host="10.20.30.40",
            db_sslmode="verify-full",
            db_sslrootcert=str(tmp_path / "missing.crt"),
        )


def _settings(**values: Any) -> Settings:
    return Settings(_env_file=None, app_env="test", db_host="10.20.30.40", **values)


def test_no_tls_context_when_disabled(clean_env: pytest.MonkeyPatch) -> None:
    settings = Settings(_env_file=None, app_env="test")
    assert db.db_ssl_context(settings) is None
    # Explicitly off: asyncpg's default would try TLS without checking anything.
    assert db.ssl_connect_args(settings) == {"ssl": False}


def test_prefer_is_passed_to_asyncpg(clean_env: pytest.MonkeyPatch) -> None:
    settings = _settings()
    assert db.db_ssl_context(settings) is None
    assert db.ssl_connect_args(settings) == {"ssl": "prefer"}


def test_verify_full_checks_the_chain_and_the_name(clean_env: pytest.MonkeyPatch) -> None:
    context = db.db_ssl_context(_settings(db_sslmode="verify-full"))
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_verify_ca_checks_the_chain_only(clean_env: pytest.MonkeyPatch) -> None:
    context = db.db_ssl_context(_settings(db_sslmode="verify-ca"))
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is False


def test_root_cert_is_the_trust_anchor(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = tmp_path / "db-ca.crt"
    ca.write_text("x")
    seen: list[str | None] = []
    real = ssl.create_default_context

    def fake(*, cafile: str | None = None) -> ssl.SSLContext:
        seen.append(cafile)
        return real()

    monkeypatch.setattr(db.ssl, "create_default_context", fake)
    args = db.ssl_connect_args(_settings(db_sslmode="verify-full", db_sslrootcert=str(ca)))
    assert seen == [str(ca)]
    assert isinstance(args["ssl"], ssl.SSLContext)


async def test_prefer_connects_with_or_without_tls_on_the_server(settings: Settings) -> None:
    """asyncpg takes "prefer" through SQLAlchemy and falls back when the
    server has no TLS (the local test server may have it or not)."""
    engine = db.create_engine(settings.model_copy(update={"db_sslmode": "prefer"}))
    try:
        await db.ping_database(engine)
        assert isinstance(await db.connection_is_encrypted(engine), bool)
    finally:
        await engine.dispose()


@pytest.mark.parametrize(("encrypted", "level"), [(True, "info"), (False, "warning")])
async def test_startup_logs_whether_a_remote_database_is_encrypted(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, encrypted: bool, level: str
) -> None:
    async def tls(_engine: object) -> bool:
        return encrypted

    monkeypatch.setattr(main, "connection_is_encrypted", tls)
    # The engine reaches the local test database; the settings claim another host.
    remote = settings.model_copy(update={"db_host": "10.20.30.40"})
    engine = create_async_engine(db.database_url(settings), poolclass=NullPool)
    try:
        with capture_logs() as logs:
            await main.check_database(engine, remote)
    finally:
        await engine.dispose()
    entries = [e for e in logs if e["event"] == "database_tls"]
    assert [(e["log_level"], e["encrypted"]) for e in entries] == [(level, encrypted)]


async def test_startup_says_nothing_about_tls_for_a_local_database(settings: Settings) -> None:
    engine = create_async_engine(db.database_url(settings), poolclass=NullPool)
    try:
        with capture_logs() as logs:
            await main.check_database(engine, settings)
    finally:
        await engine.dispose()
    assert not [e for e in logs if e["event"] == "database_tls"]
