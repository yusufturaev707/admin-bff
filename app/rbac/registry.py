"""Permission registry: every permission that exists, declared in code.

The registry is the source of truth: the startup check refuses routes that
require a permission missing from it.
"""

from collections.abc import Iterable, Iterator

from app.rbac.permissions import (
    CORE_PERMISSIONS,
    SYSTEM_DISPLAY_NAMES,
    PermissionSpec,
    pattern_matches,
)


class PermissionRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, PermissionSpec] = {}
        self._display_names: dict[str, str] = {}

    def register(
        self, specs: Iterable[PermissionSpec], *, system_id: str, display_name: str
    ) -> None:
        """Adds the permissions of one system; each must start with `system_id:`."""
        self._display_names[system_id] = display_name
        for spec in specs:
            if spec.system_id != system_id:
                raise ValueError(f"permission {spec.code!r} must start with '{system_id}:'")
            if spec.code in self._specs:
                raise ValueError(f"permission {spec.code!r} is declared twice")
            self._specs[spec.code] = spec

    def __contains__(self, code: object) -> bool:
        return code in self._specs

    def __iter__(self) -> Iterator[PermissionSpec]:
        return iter(sorted(self._specs.values(), key=lambda s: s.code))

    def display_name(self, system_id: str) -> str:
        return self._display_names.get(system_id, system_id)

    def matching(self, pattern: str) -> list[PermissionSpec]:
        return [spec for spec in self if pattern_matches(pattern, spec.code)]

    def grouped(self) -> list[tuple[str, list[PermissionSpec]]]:
        groups: dict[str, list[PermissionSpec]] = {}
        for spec in self:
            groups.setdefault(spec.system_id, []).append(spec)
        return sorted(groups.items())


def build_registry() -> PermissionRegistry:
    registry = PermissionRegistry()
    for system_id in sorted({spec.system_id for spec in CORE_PERMISSIONS}):
        registry.register(
            (s for s in CORE_PERMISSIONS if s.system_id == system_id),
            system_id=system_id,
            display_name=SYSTEM_DISPLAY_NAMES[system_id],
        )
    # Phase 5: connectors from config/systems.yaml register their permissions here.
    return registry
