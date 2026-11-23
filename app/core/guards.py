"""Marks FastAPI dependencies that guard a route (deny-by-default, section 7).

`app.rbac.route_check` refuses to start the app if a route is neither public
nor depends on a marked guard. A guard may also name the exact permissions it
requires, so the startup check can verify they are declared in the registry.
"""

from collections.abc import Callable, Iterable
from typing import Any

_GUARD_ATTR = "__admin_bff_guard__"


def mark_guard[F: Callable[..., Any]](func: F, permissions: Iterable[str] = ()) -> F:
    setattr(func, _GUARD_ATTR, frozenset(permissions))
    return func


def guard_permissions(func: object) -> frozenset[str] | None:
    """None if `func` is not a guard; otherwise the permissions it requires."""
    value = getattr(func, _GUARD_ATTR, None)
    return value if isinstance(value, frozenset) else None
