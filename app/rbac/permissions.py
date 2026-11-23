"""Permissions: `system:resource:action` (section 7).

* A route requires an exact permission, never a wildcard.
* An admin is granted patterns through roles: exact codes or wildcards per
  segment, e.g. `faceid:*:read`, `faceid:*:*`, `*:*:*`.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

_SEGMENT = r"[a-z][a-z0-9_]*"
PERMISSION_RE = re.compile(rf"^{_SEGMENT}:{_SEGMENT}:{_SEGMENT}$")
PATTERN_RE = re.compile(rf"^(\*|{_SEGMENT}):(\*|{_SEGMENT}):(\*|{_SEGMENT})$")
WILDCARD = "*"
ALL_PERMISSIONS = "*:*:*"


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    code: str
    description: str  # Uzbek, shown in the role editor (required)

    def __post_init__(self) -> None:
        if not PERMISSION_RE.fullmatch(self.code):
            raise ValueError(f"permission {self.code!r} is not 'system:resource:action'")
        if not self.description.strip():
            raise ValueError(f"permission {self.code!r} needs a description")

    @property
    def system_id(self) -> str:
        return self.code.split(":", 1)[0]


def is_valid_pattern(pattern: str) -> bool:
    return PATTERN_RE.fullmatch(pattern) is not None


def pattern_covers(holder: str, pattern: str) -> bool:
    """Is everything `pattern` grants also granted by `holder`? `pattern` may be
    an exact permission or itself a wildcard pattern (privilege escalation check:
    an admin may only hand out what it holds)."""
    held = holder.split(":")
    given = pattern.split(":")
    return len(held) == len(given) == 3 and all(
        h in (WILDCARD, g) for h, g in zip(held, given, strict=True)
    )


def pattern_matches(pattern: str, permission: str) -> bool:
    """Does a granted `pattern` allow the exact `permission`?"""
    return pattern_covers(pattern, permission)


def any_covers(holders: Iterable[str], pattern: str) -> bool:
    return any(pattern_covers(holder, pattern) for holder in holders)


# Permissions of the core (section 7: `admin:*`, `audit:*`). Systems declare
# theirs in app/connectors/<system_id>/permissions.py (Phase 5).
CORE_PERMISSIONS = (
    PermissionSpec("admin:users:read", "Adminlar ro'yxati va ma'lumotlarini ko'rish"),
    PermissionSpec(
        "admin:users:write", "Admin yaratish va tahrirlash, bloklash, rol va hudud berish"
    ),
    PermissionSpec(
        "admin:users:security",
        "Admin parolini va TOTP'ini tiklash, login blokini muddatidan oldin ochish",
    ),
    PermissionSpec("admin:roles:read", "Rollar va permission'lar ro'yxatini ko'rish"),
    PermissionSpec("admin:roles:write", "Rol yaratish, tahrirlash va o'chirish"),
    PermissionSpec("admin:api:docs", "API hujjatini (Swagger) ko'rish"),
    PermissionSpec("audit:logs:read", "Audit log'ni ko'rish: kim, qachon, nima qildi"),
    PermissionSpec(
        "audit:logs:export",
        "Audit log'ni CSV faylga eksport qilish (yozuvlarni ko'rish ham shunga kiradi)",
    ),
)

SYSTEM_DISPLAY_NAMES = {"admin": "Adminka boshqaruvi", "audit": "Audit"}
