"""Request and response models of /api/v1/me and /api/v1/admin."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.auth.models import AuthMethod


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RoleRef(BaseModel):
    id: uuid.UUID
    name: str


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    full_name: str | None
    is_active: bool
    auth_methods: list[AuthMethod]
    must_change_password: bool
    imie_masked: str | None
    org_id: int | None
    region_id: int | None
    roles: list[RoleRef]
    created_at: datetime
    last_login_at: datetime | None


class UserCreated(UserOut):
    initial_password: str | None = Field(
        description="Vaqtinchalik parol: faqat shu javobda, bir marta ko'rsatiladi"
    )


class UserCreate(_Request):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "operator_toshkent",
                "full_name": "Aliyev Vali",
                "auth_methods": ["password"],
                "org_id": 1,
                "role_ids": [],
            }
        }
    )

    username: str = Field(min_length=3, max_length=64)
    full_name: str | None = Field(default=None, max_length=128)
    auth_methods: list[AuthMethod] = Field(default=[AuthMethod.PASSWORD], min_length=1)
    imie: str | None = Field(
        default=None,
        pattern=r"^[0-9]{14}$",
        description=(
            "OneID uchun fuqaroning IMIE (PINFL) raqami, 14 ta raqam. Saqlanmaydi: "
            "faqat HMAC va maskalangan ko'rinishi"
        ),
    )
    org_id: int | None = Field(
        default=None,
        ge=1,
        description="Tashkilot. region_id berilmasa, tashkilotning hududi olinadi",
    )
    region_id: int | None = Field(default=None, ge=1)
    role_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class UserUpdate(_Request):
    """Only the fields that are sent are changed; `imie: null` unlinks OneID.
    A new `org_id` without `region_id` moves the user to that organization's region."""

    full_name: str | None = Field(default=None, max_length=128)
    is_active: bool | None = None
    auth_methods: list[AuthMethod] | None = Field(default=None, min_length=1)
    imie: str | None = Field(
        default=None,
        pattern=r"^[0-9]{14}$",
        description=(
            "OneID uchun fuqaroning IMIE (PINFL) raqami, 14 ta raqam. Saqlanmaydi: "
            "faqat HMAC va maskalangan ko'rinishi"
        ),
    )
    org_id: int | None = Field(default=None, ge=1)
    region_id: int | None = Field(default=None, ge=1)


class UserUpdated(UserOut):
    initial_password: str | None = Field(
        default=None, description="Parol usuli yangi qo'shilganda: vaqtinchalik parol"
    )


class RolesUpdate(_Request):
    role_ids: list[uuid.UUID] = Field(max_length=50)


class PasswordReset(BaseModel):
    initial_password: str = Field(description="Vaqtinchalik parol, bir marta ko'rsatiladi")


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    is_system: bool
    permissions: list[str]
    user_count: int
    created_at: datetime
    updated_at: datetime


class RoleCreate(_Request):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "auditor",
                "description": "Faqat ko'rish",
                "permissions": ["admin:users:read", "admin:roles:read"],
            }
        }
    )

    name: str = Field(min_length=2, max_length=64)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(max_length=500)


class RoleUpdate(_Request):
    name: str | None = Field(default=None, min_length=2, max_length=64)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = Field(default=None, max_length=500)


class PermissionItem(BaseModel):
    code: str
    description: str


class PermissionGroup(BaseModel):
    system_id: str
    display_name: str
    permissions: list[PermissionItem]


class PermissionCatalogue(BaseModel):
    groups: list[PermissionGroup]


class MeOut(BaseModel):
    """The current admin: the frontend builds its menu from `permissions`."""

    id: uuid.UUID
    username: str
    full_name: str | None
    auth_methods: list[AuthMethod]
    must_change_password: bool
    org_id: int | None
    region_id: int | None
    roles: list[RoleRef]
    permissions: list[str] = Field(description="Berilgan permission'lar, wildcard bo'lishi mumkin")


UserSort = Literal[
    "username", "-username", "created_at", "-created_at", "last_login_at", "-last_login_at"
]
