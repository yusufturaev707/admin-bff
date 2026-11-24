"""Admin DB tables of the auth module.

Roles and permissions are in app.rbac.models, the audit log in app.audit.models.
"""

import re
import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    String,
    Text,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

import app.directory.models  # noqa: F401  (users.org_id/region_id refer to its tables)
from app.core.db import Base

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def normalize_username(value: str) -> str | None:
    """Usernames are case-insensitive: stored and compared in lower case."""
    username = value.strip().lower()
    return username if _USERNAME_RE.fullmatch(username) else None


class AuthMethod(StrEnum):
    PASSWORD = "password"  # noqa: S105 - a method name, not a secret  # nosec B105
    ONEID = "oneid"  # citizen's OneID


class User(Base):
    """A user of the admin panel (was `admin_users`, renamed 2026-11-24)."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username = lower(username)", name="username_lowercase"),
        CheckConstraint(
            "cardinality(auth_methods) > 0 AND auth_methods <@ ARRAY['password', 'oneid']::text[]",
            name="auth_methods_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(128))

    # Null for an admin who may only sign in with OneID.
    password_hash: Mapped[str | None] = mapped_column(Text)
    password_changed_at: Mapped[datetime | None]
    must_change_password: Mapped[bool] = mapped_column(server_default=true())

    # Which primary methods this admin may use; set by the superadmin.
    auth_methods: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default=text("ARRAY['password']::text[]")
    )

    # OneID link: HMAC-SHA256 of the citizen's IMIE (PINFL, 14 digits) for the
    # lookup and its masked form for display. The IMIE itself is not stored.
    oneid_imie_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    imie_masked: Mapped[str | None] = mapped_column(String(16))

    # Where the user works (app.directory). RESTRICT: an organization or a
    # region still in use cannot be deleted.
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), index=True
    )
    region_id: Mapped[int | None] = mapped_column(
        ForeignKey("regions.id", ondelete="RESTRICT"), index=True
    )

    is_active: Mapped[bool] = mapped_column(server_default=true())
    # Bumped when roles change (Phase 2); sessions carry the version they saw.
    perm_version: Mapped[int] = mapped_column(server_default=text("0"))

    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    last_login_at: Mapped[datetime | None]

    def allows(self, method: AuthMethod) -> bool:
        return method.value in self.auth_methods
