"""users (was admin_users) with IMIE names, regions and organizations

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-24

Owner's decision, 2026-11-24:

* `admin_users` becomes `users`, renamed in place, so its rows stay. The
  constraint and index names follow the table, as the naming convention
  (app.core.db) would give them for a new table.
* `oneid_pinfl_hash` -> `oneid_imie_hash`, `pinfl_masked` -> `imie_masked`.
* New `regions` and `organizations` (integer ids, `status` true = active).
  A user may belong to one organization and one region (`org_id`,
  `region_id`, both optional). ON DELETE RESTRICT: nothing in use can be
  deleted.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# old name -> new name, on the renamed table
_USER_CONSTRAINTS = {
    "pk_admin_users": "pk_users",
    "uq_admin_users_username": "uq_users_username",
    "uq_admin_users_oneid_pinfl_hash": "uq_users_oneid_imie_hash",
    "ck_admin_users_username_lowercase": "ck_users_username_lowercase",
    "ck_admin_users_auth_methods_valid": "ck_users_auth_methods_valid",
}
_USER_ROLES_FK = ("fk_user_roles_user_id_admin_users", "fk_user_roles_user_id_users")


def _timestamps() -> list[sa.Column[object]]:
    return [
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "regions",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("dtm_id", sa.Integer(), nullable=True),
        sa.Column("p_code", sa.String(length=32), nullable=True),
        sa.Column("status", sa.Boolean(), server_default=sa.true(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_regions")),
        sa.UniqueConstraint("name", name=op.f("uq_regions_name")),
        sa.UniqueConstraint("dtm_id", name=op.f("uq_regions_dtm_id")),
    )
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), sa.Identity(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("region_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.Boolean(), server_default=sa.true(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["region_id"],
            ["regions.id"],
            name=op.f("fk_organizations_region_id_regions"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("region_id", "name", name="uq_organizations_region_id_name"),
    )
    op.create_index(op.f("ix_organizations_region_id"), "organizations", ["region_id"])

    op.rename_table("admin_users", "users")
    for old, new in _USER_CONSTRAINTS.items():
        op.execute(f"ALTER TABLE users RENAME CONSTRAINT {old} TO {new}")
    op.execute(
        f"ALTER TABLE user_roles RENAME CONSTRAINT {_USER_ROLES_FK[0]} TO {_USER_ROLES_FK[1]}"
    )
    op.alter_column("users", "oneid_pinfl_hash", new_column_name="oneid_imie_hash")
    op.alter_column("users", "pinfl_masked", new_column_name="imie_masked")

    op.add_column("users", sa.Column("org_id", sa.Integer(), nullable=True))
    op.add_column("users", sa.Column("region_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        op.f("fk_users_org_id_organizations"),
        "users",
        "organizations",
        ["org_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        op.f("fk_users_region_id_regions"),
        "users",
        "regions",
        ["region_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(op.f("ix_users_org_id"), "users", ["org_id"])
    op.create_index(op.f("ix_users_region_id"), "users", ["region_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_users_region_id"), table_name="users")
    op.drop_index(op.f("ix_users_org_id"), table_name="users")
    op.drop_constraint(op.f("fk_users_region_id_regions"), "users", type_="foreignkey")
    op.drop_constraint(op.f("fk_users_org_id_organizations"), "users", type_="foreignkey")
    op.drop_column("users", "region_id")
    op.drop_column("users", "org_id")

    op.alter_column("users", "imie_masked", new_column_name="pinfl_masked")
    op.alter_column("users", "oneid_imie_hash", new_column_name="oneid_pinfl_hash")
    op.execute(
        f"ALTER TABLE user_roles RENAME CONSTRAINT {_USER_ROLES_FK[1]} TO {_USER_ROLES_FK[0]}"
    )
    for old, new in _USER_CONSTRAINTS.items():
        op.execute(f"ALTER TABLE users RENAME CONSTRAINT {new} TO {old}")
    op.rename_table("users", "admin_users")

    op.drop_index(op.f("ix_organizations_region_id"), table_name="organizations")
    op.drop_table("organizations")
    op.drop_table("regions")
