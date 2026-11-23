"""Request and response models of /api/v1/auth (part of the frontend contract)."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.auth.models import AuthMethod
from app.auth.passwords import MAX_LENGTH
from app.auth.sessions import PendingStep

# Stands for secret values (passwords, tokens) in the OpenAPI examples.
_PLACEHOLDER = "..."

_CODE = Field(pattern=r"^[0-9]{6}$", description="Autentifikator ilovasidagi 6 xonali kod")


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Request):
    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "operator_toshkent", "password": _PLACEHOLDER}}
    )

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)


class LoginResponse(BaseModel):
    """Either `mfa_required` (continue with /auth/mfa) or, on the very first
    sign-in, a setup session (`setup_required`, cookie set, `csrf_token`)."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"mfa_required": True, "mfa_token": _PLACEHOLDER, "setup_required": False},
                {
                    "mfa_required": False,
                    "setup_required": True,
                    "pending": ["totp_enrollment", "password_change"],
                    "csrf_token": _PLACEHOLDER,
                },
            ]
        }
    )

    mfa_required: bool
    mfa_token: str | None = Field(default=None, description="Bir martalik, 5 daqiqa amal qiladi")
    setup_required: bool = False
    pending: list[PendingStep] = Field(default_factory=list)
    csrf_token: str | None = None


class MfaRequest(_Request):
    model_config = ConfigDict(
        json_schema_extra={"example": {"mfa_token": _PLACEHOLDER, "code": "123456"}}
    )

    mfa_token: str = Field(min_length=1, max_length=128)
    code: str | None = Field(default=None, pattern=r"^[0-9]{6}$")
    recovery_code: str | None = Field(default=None, min_length=16, max_length=24)

    @model_validator(mode="after")
    def _exactly_one_factor(self) -> Self:
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("send either code or recovery_code")
        return self


class SessionStartedResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"csrf_token": _PLACEHOLDER, "setup_required": False, "pending": []}
        }
    )

    csrf_token: str = Field(description="Har bir POST/PUT/PATCH/DELETE'da X-CSRF-Token sarlavhasi")
    setup_required: bool
    pending: list[PendingStep]


class SessionInfo(BaseModel):
    """The current session; also gives the CSRF token back after a page reload."""

    id: str
    user_id: str
    username: str
    auth_method: AuthMethod
    created_at: datetime
    last_seen: datetime
    expires_at: datetime
    mfa_at: datetime | None
    setup_required: bool
    pending: list[PendingStep]
    csrf_token: str


class SessionListItem(BaseModel):
    id: str
    auth_method: AuthMethod
    created_at: datetime
    last_seen: datetime
    ip: str
    user_agent: str
    current: bool


class SessionList(BaseModel):
    items: list[SessionListItem]


class PasswordChangeRequest(_Request):
    old_password: str = Field(min_length=1, max_length=MAX_LENGTH)
    new_password: str = Field(min_length=1, max_length=MAX_LENGTH)
    code: str | None = Field(
        default=None,
        pattern=r"^[0-9]{6}$",
        description="TOTP kod. Faqat TOTP o'chirilgan development muhitida yuborilmaydi",
    )


class TotpEnrollResponse(BaseModel):
    """Shown once. The frontend draws `otpauth_uri` as a QR code locally."""

    secret: str
    otpauth_uri: str


class CodeRequest(_Request):
    code: str = _CODE


class TotpConfirmResponse(SessionStartedResponse):
    recovery_codes: list[str] = Field(
        description="10 ta bir martalik kod, faqat bir marta ko'rsatiladi"
    )


class StepUpResponse(BaseModel):
    mfa_at: datetime
