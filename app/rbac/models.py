"""RBAC tables (section 7): roles, permissions, role_permissions, user_roles."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, false, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

SUPERADMIN_ROLE = "superadmin"
# Serialises the changes that can leave fewer active superadmins
# (pg_advisory_xact_lock). int.from_bytes(b"superadm").
SUPERADMIN_LOCK_KEY = 8319679467649852525

# Mirrors app.rbac.permissions.PATTERN_RE, so the DB itself refuses garbage.
_PATTERN_SQL = r"permission ~ '^(\*|[a-z][a-z0-9_]*):(\*|[a-z][a-z0-9_]*):(\*|[a-z][a-z0-9_]*)$'"


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(Text, server_default="")
    # The seeded `superadmin` role: not editable or deletable through the API.
    is_system: Mapped[bool] = mapped_column(server_default=false())
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class Permission(Base):
    """Catalogue of declared permissions. The registry in code is the source of
    truth; nothing copies it here since the CLI (`sync-permissions`) was
    removed on 2026-11-23."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    system_id: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class RolePermission(Base):
    """An exact permission or a wildcard pattern granted by a role."""

    __tablename__ = "role_permissions"
    __table_args__ = (CheckConstraint(_PATTERN_SQL, name="permission_pattern"),)

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission: Mapped[str] = mapped_column(String(128), primary_key=True)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("admin_users.id", ondelete="CASCADE"), primary_key=True
    )
    # RESTRICT: a role that is still assigned cannot be deleted (section 7).
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
