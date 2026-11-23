"""rbac tables: roles, permissions, role_permissions, user_roles, user_scopes

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PATTERN_SQL = r"permission ~ '^(\*|[a-z][a-z0-9_]*):(\*|[a-z][a-z0-9_]*):(\*|[a-z][a-z0-9_]*)$'"


def _now(name: str) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False)


def upgrade() -> None:
    op.add_column("admin_users", sa.Column("full_name", sa.String(length=128), nullable=True))

    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("is_system", sa.Boolean(), server_default=sa.false(), nullable=False),
        _now("created_at"),
        _now("updated_at"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )
    op.create_table(
        "permissions",
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("system_id", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        _now("updated_at"),
        sa.PrimaryKeyConstraint("code", name=op.f("pk_permissions")),
    )
    op.create_index(op.f("ix_permissions_system_id"), "permissions", ["system_id"])
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission", sa.String(length=128), nullable=False),
        sa.CheckConstraint(_PATTERN_SQL, name=op.f("ck_role_permissions_permission_pattern")),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission", name=op.f("pk_role_permissions")),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        _now("created_at"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.id"],
            name=op.f("fk_user_roles_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_user_roles_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id", name=op.f("pk_user_roles")),
    )
    op.create_index(op.f("ix_user_roles_role_id"), "user_roles", ["role_id"])
    op.create_table(
        "user_scopes",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("scope_type", sa.String(length=16), nullable=False),
        sa.Column("scope_value", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "scope_type IN ('region', 'zone', 'branch')",
            name=op.f("ck_user_scopes_scope_type_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["admin_users.id"],
            name=op.f("fk_user_scopes_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "user_id", "scope_type", "scope_value", name=op.f("pk_user_scopes")
        ),
    )


def downgrade() -> None:
    op.drop_table("user_scopes")
    op.drop_index(op.f("ix_user_roles_role_id"), table_name="user_roles")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_index(op.f("ix_permissions_system_id"), table_name="permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
    op.drop_column("admin_users", "full_name")
