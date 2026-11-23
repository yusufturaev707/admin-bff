"""Permission patterns, registry and principal checks."""

import uuid

import pytest

from app.rbac.permissions import (
    CORE_PERMISSIONS,
    PermissionSpec,
    is_valid_pattern,
    pattern_covers,
    pattern_matches,
)
from app.rbac.principal import Principal
from app.rbac.registry import PermissionRegistry, build_registry


@pytest.mark.parametrize(
    ("pattern", "permission", "allowed"),
    [
        ("faceid:students:read", "faceid:students:read", True),
        ("faceid:*:read", "faceid:students:read", True),
        ("faceid:*:read", "faceid:students:write", False),
        ("faceid:*:*", "faceid:cameras:write", True),
        ("faceid:*:*", "proctoring:sessions:read", False),
        ("*:*:*", "proctoring:sessions:terminate", True),
        ("*:students:read", "faceid:students:read", True),
        ("faceid:students", "faceid:students:read", False),
    ],
)
def test_wildcard_matching(pattern: str, permission: str, allowed: bool) -> None:
    assert pattern_matches(pattern, permission) is allowed


@pytest.mark.parametrize(
    ("holder", "given", "covered"),
    [
        ("*:*:*", "faceid:*:*", True),
        ("faceid:*:*", "faceid:*:read", True),
        ("faceid:*:read", "faceid:*:*", False),  # cannot hand out more than it holds
        ("faceid:students:read", "faceid:*:read", False),
        ("faceid:*:read", "faceid:students:read", True),
    ],
)
def test_pattern_coverage(holder: str, given: str, covered: bool) -> None:
    assert pattern_covers(holder, given) is covered


def test_pattern_validation() -> None:
    for good in ("faceid:students:read", "faceid:*:read", "*:*:*"):
        assert is_valid_pattern(good)
    for bad in ("faceid:students", "FaceID:x:y", "faceid:**:read", "a:b:c:d", "faceid: x:y"):
        assert not is_valid_pattern(bad)


def test_permission_spec_and_registry_rules() -> None:
    with pytest.raises(ValueError, match="system:resource:action"):
        PermissionSpec("faceid:*:read", "wildcards are not declared")
    with pytest.raises(ValueError, match="description"):
        PermissionSpec("faceid:students:read", " ")

    registry = PermissionRegistry()
    spec = PermissionSpec("faceid:students:read", "Talabalarni ko'rish")
    registry.register([spec], system_id="faceid", display_name="Face-ID")
    with pytest.raises(ValueError, match="declared twice"):
        registry.register([spec], system_id="faceid", display_name="Face-ID")
    with pytest.raises(ValueError, match="must start with 'proctoring:'"):
        registry.register([spec], system_id="proctoring", display_name="Proctoring")
    assert "faceid:students:read" in registry
    assert [s.code for s in registry.matching("faceid:*:*")] == ["faceid:students:read"]


def test_core_registry_is_complete() -> None:
    registry = build_registry()
    assert {s.code for s in registry} == {s.code for s in CORE_PERMISSIONS}
    assert [system for system, _ in registry.grouped()] == ["admin", "audit"]


def test_principal_checks() -> None:
    principal = Principal(
        user_id=uuid.uuid4(),
        username="op",
        full_name=None,
        permissions=frozenset({"faceid:*:read", "admin:users:read"}),
    )
    assert principal.has("faceid:students:read")
    assert not principal.has("faceid:students:write")
    assert principal.covers("faceid:cameras:read")
    assert not principal.covers("faceid:*:*")
