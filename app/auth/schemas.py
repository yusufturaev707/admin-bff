"""Request and response models of /api/v1/auth (part of the frontend contract)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.auth.models import AuthMethod
from app.auth.passwords import MAX_LENGTH
from app.auth.sessions import PendingStep

# Stands for secret values (passwords, tokens) in the OpenAPI examples.
_PLACEHOLDER = "..."


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Request):
    model_config = ConfigDict(
        json_schema_extra={"example": {"username": "operator_toshkent", "password": _PLACEHOLDER}}
    )

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)


class SessionStartedResponse(BaseModel):
    """The session cookie is set. On the first sign-in `pending` lists what is
    left (`password_change`); until then only /auth/* works."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"csrf_token": _PLACEHOLDER, "setup_required": False, "pending": []},
                {
                    "csrf_token": _PLACEHOLDER,
                    "setup_required": True,
                    "pending": ["password_change"],
                },
            ]
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
