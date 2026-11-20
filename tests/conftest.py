import pytest

from app.settings import Settings

FRONTEND_ORIGIN = "https://admin.test.uz"

# Env vars that would otherwise leak a developer's local configuration into tests.
_SETTINGS_ENV_VARS = [name.upper() for name in Settings.model_fields] + ["CREDENTIALS_DIRECTORY"]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in _SETTINGS_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def settings(clean_env: pytest.MonkeyPatch) -> Settings:
    return Settings(
        _env_file=None,
        app_env="test",
        log_format="json",
        log_level="INFO",
        frontend_origin=FRONTEND_ORIGIN,
    )
