"""TLS to a database on another server (DB_SSLMODE, DB_SSLROOTCERT)."""

import ssl
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

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
def test_production_refuses_plain_text_to_another_host(
    clean_env: pytest.MonkeyPatch, host: str
) -> None:
    with pytest.raises(ValidationError, match="DB_SSLMODE"):
        Settings(_env_file=None, db_host=host)


@pytest.mark.parametrize("host", ["/var/run/postgresql", "127.0.0.1", "localhost"])
def test_production_accepts_plain_text_on_the_same_host(
    clean_env: pytest.MonkeyPatch, host: str
) -> None:
    assert Settings(_env_file=None, db_host=host).db_sslmode == "disable"


@pytest.mark.parametrize("mode", ["verify-full", "verify-ca"])
def test_production_accepts_tls_to_another_host(
    clean_env: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    ca = tmp_path / "db-ca.crt"
    ca.write_text("not parsed by the settings")
    settings = Settings(
        _env_file=None, db_host="10.20.30.40", db_sslmode=mode, db_sslrootcert=str(ca)
    )
    assert settings.db_sslmode == mode


def test_development_allows_plain_text_to_another_host(clean_env: pytest.MonkeyPatch) -> None:
    Settings(_env_file=None, app_env="development", log_format="console", db_host="10.0.0.5")


@pytest.mark.parametrize("mode", ["require", "prefer", "allow"])
def test_modes_without_certificate_check_do_not_exist(
    clean_env: pytest.MonkeyPatch, mode: str
) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", db_host="10.0.0.5", db_sslmode=mode)


def test_tls_on_a_unix_socket_is_refused(clean_env: pytest.MonkeyPatch) -> None:
    # PostgreSQL never encrypts a unix socket: the setting would only look safe.
    with pytest.raises(ValidationError, match="unix socket"):
        Settings(_env_file=None, db_host="/var/run/postgresql", db_sslmode="verify-full")


def test_root_cert_without_tls_is_refused(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca = tmp_path / "db-ca.crt"
    ca.write_text("x")
    with pytest.raises(ValidationError, match="DB_SSLROOTCERT"):
        Settings(_env_file=None, app_env="test", db_sslrootcert=str(ca))


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
