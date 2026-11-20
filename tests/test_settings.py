import secrets
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.settings import Settings, load_settings


def test_defaults_are_production_safe(clean_env: pytest.MonkeyPatch) -> None:
    settings = Settings(_env_file=None)
    assert settings.app_env == "production"
    assert settings.is_production
    assert settings.log_format == "json"
    assert settings.frontend_origin is None


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.uzbmb.uz",
        "https://admin.uzbmb.uz/app",
        "https://admin.uzbmb.uz?x=1",
        "ftp://admin.uzbmb.uz",
        "https://user:pw@admin.uzbmb.uz",
        "admin.uzbmb.uz",
    ],
)
def test_frontend_origin_rejects_non_origins(clean_env: pytest.MonkeyPatch, origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="test", frontend_origin=origin)


def test_frontend_origin_is_normalised(clean_env: pytest.MonkeyPatch) -> None:
    settings = Settings(_env_file=None, app_env="test", frontend_origin="https://admin.uzbmb.uz/")
    assert settings.frontend_origin == "https://admin.uzbmb.uz"


def test_production_requires_https_origin(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, frontend_origin="http://admin.uzbmb.uz")


def test_production_requires_json_logs(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_format="console")


def test_redis_password_is_not_allowed_in_url(clean_env: pytest.MonkeyPatch) -> None:
    password = secrets.token_urlsafe(12)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, redis_url=f"redis://:{password}@127.0.0.1:6379/0")


def test_secrets_are_read_from_credentials_directory_and_env_file_is_ignored(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_password = secrets.token_urlsafe(24)
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "db_password").write_text(db_password, encoding="utf-8")
    (tmp_path / ".env").write_text("DB_NAME=from_dotenv\n", encoding="utf-8")

    clean_env.chdir(tmp_path)
    clean_env.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    settings = load_settings()

    assert settings.db_password is not None
    assert settings.db_password.get_secret_value() == db_password
    assert settings.db_name == "admin_bff"  # .env was not read
    assert db_password not in repr(settings)


def test_empty_secret_means_not_set(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("DB_PASSWORD", "")
    clean_env.setenv("REDIS_PASSWORD", "")
    settings = Settings(_env_file=None)
    assert settings.db_password is None
    assert settings.redis_password is None


def test_env_file_is_read_in_development(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("APP_ENV=development\nDB_NAME=from_dotenv\n", encoding="utf-8")
    clean_env.chdir(tmp_path)
    settings = load_settings()
    assert settings.app_env == "development"
    assert settings.db_name == "from_dotenv"
