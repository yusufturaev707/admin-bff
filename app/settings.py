"""Application settings.

Values come from (highest priority first): constructor arguments, environment
variables, `.env` (development only), secret files in `$CREDENTIALS_DIRECTORY`
(systemd `LoadCredential=`), defaults.

When `$CREDENTIALS_DIRECTORY` is set (i.e. the service runs under systemd), the
`.env` file is never read, so a stray `.env` on a server cannot override
production configuration.
"""

import base64
import binascii
import os
import re
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
LogFormat = Literal["json", "console"]

_REDIS_PREFIX_RE = re.compile(r"^[A-Za-z0-9:_-]{0,64}$")

# OWASP minimum for Argon2id (m=19 MiB, t=2). Weaker parameters are only
# allowed outside production (tests use them to stay fast).
_ARGON2_MIN_MEMORY_KIB = 19 * 1024
_ARGON2_MIN_TIME_COST = 2


def decode_key(value: SecretStr, *, min_bytes: int, max_bytes: int | None = None) -> bytes:
    """Decodes a base64 key from settings and checks its length."""
    try:
        raw = base64.b64decode(value.get_secret_value(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("must be base64") from exc
    if len(raw) < min_bytes or (max_bytes is not None and len(raw) > max_bytes):
        expected = f"{min_bytes}" if max_bytes == min_bytes else f">= {min_bytes}"
        raise ValueError(f"must decode to {expected} bytes")
    return raw


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
    # Prepended to every key. Empty in production (the sessions Redis belongs to
    # the BFF alone); useful when a development Redis is shared with other projects.
    redis_key_prefix: str = ""

    # Timeout of a single dependency check in /ready.
    ready_timeout_s: float = Field(default=2.0, gt=0, le=10)

    # --- Auth (section 6) ---
    # AES-256-GCM key for TOTP secrets: base64 of 32 random bytes.
    # Production: systemd credential `totp_enc_key`.
    totp_enc_key: SecretStr | None = None
    # HMAC-SHA256 key for looking up an admin by PINFL (OneID): base64, >= 32 bytes.
    # Production: systemd credential `pinfl_hmac_key`.
    pinfl_hmac_key: SecretStr | None = None
    totp_issuer: str = Field(default="UZBMB Admin", min_length=1, max_length=64)

    session_idle_timeout_s: int = Field(default=30 * 60, ge=60, le=24 * 3600)
    session_absolute_timeout_s: int = Field(default=12 * 3600, ge=300, le=7 * 24 * 3600)

    # Argon2id cost. Defaults are argon2-cffi's (RFC 9106 low-memory profile).
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost_kib: int = Field(default=64 * 1024, ge=8, le=1024 * 1024)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)

    # --- OneID (template, section 6) ---
    # The client itself is not implemented yet (TODO(owner): OneID integration
    # documents). While it is missing, enabling OneID stops the startup.
    oneid_enabled: bool = False
    oneid_client_id: str | None = None
    # Production: systemd credential `oneid_client_secret`.
    oneid_client_secret: SecretStr | None = None
    oneid_redirect_uri: str | None = None

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def totp_key(self) -> bytes:
        if self.totp_enc_key is None:
            raise RuntimeError("TOTP_ENC_KEY is not configured (systemd credential totp_enc_key)")
        return decode_key(self.totp_enc_key, min_bytes=32, max_bytes=32)

    def pinfl_key(self) -> bytes:
        if self.pinfl_hmac_key is None:
            raise RuntimeError(
                "PINFL_HMAC_KEY is not configured (systemd credential pinfl_hmac_key)"
            )
        return decode_key(self.pinfl_hmac_key, min_bytes=32)

    @field_validator("totp_enc_key")
    @classmethod
    def _validate_totp_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            decode_key(value, min_bytes=32, max_bytes=32)
        return value

    @field_validator("pinfl_hmac_key")
    @classmethod
    def _validate_pinfl_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            decode_key(value, min_bytes=32)
        return value

    @field_validator("redis_key_prefix")
    @classmethod
    def _validate_redis_prefix(cls, value: str) -> str:
        if not _REDIS_PREFIX_RE.fullmatch(value):
            raise ValueError("only letters, digits, ':', '_' and '-' (max 64)")
        return value

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
            if (
                self.argon2_memory_cost_kib < _ARGON2_MIN_MEMORY_KIB
                or self.argon2_time_cost < _ARGON2_MIN_TIME_COST
            ):
                raise ValueError("production requires Argon2id m >= 19 MiB and t >= 2")
        return self

    @model_validator(mode="after")
    def _validate_oneid(self) -> "Settings":
        if not self.oneid_enabled:
            return self
        missing = [
            name
            for name in ("oneid_client_id", "oneid_client_secret", "oneid_redirect_uri")
            if getattr(self, name) is None
        ]
        if self.pinfl_hmac_key is None:
            missing.append("pinfl_hmac_key")
        if self.frontend_origin is None:
            missing.append("frontend_origin")
        if missing:
            raise ValueError(f"ONEID_ENABLED requires: {', '.join(missing)}")
        redirect = urlsplit(self.oneid_redirect_uri or "")
        if redirect.scheme != "https" and self.is_production:
            raise ValueError("production requires an https:// ONEID_REDIRECT_URI")
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
