"""Application settings.

Values come from (highest priority first): constructor arguments, environment
variables, `.env` (development only), secret files in `$CREDENTIALS_DIRECTORY`
(systemd `LoadCredential=`), defaults.

When `$CREDENTIALS_DIRECTORY` is set (i.e. the service runs under systemd), the
`.env` file is never read, so a stray `.env` on a server cannot override
production configuration.
"""

import os
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
LogFormat = Literal["json", "console"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
        # `DB_PASSWORD=` (empty) means "not set", not an empty password.
        env_ignore_empty=True,
        env_file_encoding="utf-8",
        frozen=True,
    )

    # Safe default: an unconfigured instance behaves like production
    # (no OpenAPI endpoint, JSON logs, strict validation).
    app_env: AppEnv = "production"

    log_level: LogLevel = "INFO"
    log_format: LogFormat = "json"

    # The only origin allowed by CORS and by the CSRF Origin check (section 10).
    # None means no cross-origin access at all.
    frontend_origin: str | None = None

    # Admin DB (PostgreSQL). `db_host` may be a unix socket directory.
    db_host: str = "127.0.0.1"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "admin_bff"
    db_user: str = "admin_bff"
    db_password: SecretStr | None = None
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=100)

    # Session/cache Redis. `unix:///run/redis/redis.sock` is also accepted.
    redis_url: str = "redis://127.0.0.1:6379/0"
    redis_password: SecretStr | None = None

    # Timeout of a single dependency check in /ready.
    ready_timeout_s: float = Field(default=2.0, gt=0, le=10)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @field_validator("frontend_origin")
    @classmethod
    def _validate_origin(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "*" in value:
            raise ValueError("wildcard origin is not allowed")
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
        ):
            raise ValueError("must be a bare origin, e.g. https://admin.example.uz")
        return f"{parts.scheme}://{parts.netloc}"

    @field_validator("redis_url")
    @classmethod
    def _validate_redis_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"redis", "rediss", "unix"}:
            raise ValueError("scheme must be redis://, rediss:// or unix://")
        if parts.password:
            raise ValueError("put the password into REDIS_PASSWORD (a credential), not the URL")
        return value

    @model_validator(mode="after")
    def _validate_production(self) -> "Settings":
        if self.is_production:
            if self.log_format != "json":
                raise ValueError("production requires LOG_FORMAT=json")
            if self.frontend_origin is not None and not self.frontend_origin.startswith("https://"):
                raise ValueError("production requires an https:// FRONTEND_ORIGIN")
        return self


def load_settings() -> Settings:
    """Builds settings from the environment (uncached)."""
    credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_dir:
        return Settings(_env_file=None, _secrets_dir=credentials_dir)
    return Settings(_env_file=".env")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
