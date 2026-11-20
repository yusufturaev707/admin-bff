"""Startup validation of the route table.

FastAPI (0.165+) keeps included routers lazily as `_IncludedRouter` objects, so
`app.routes` does not list the effective API routes. `iter_api_routes` walks
them through FastAPI's public `iter_route_contexts`.

Checked at startup (lifespan), so a violation stops the service from starting:

* every API route has an explicit, unique `operationId` of the form
  `<system>_<resource>_<verb>` (the frontend client is generated from them);
* Phase 2 adds the deny-by-default permission check here.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts

OPERATION_ID_RE = re.compile(r"^[a-z][a-z0-9]*_[a-z][a-z0-9_]*_[a-z]+$")


@dataclass(frozen=True, slots=True)
class RouteInfo:
    path: str
    methods: frozenset[str]
    operation_id: str | None


def iter_api_routes(app: FastAPI) -> Iterator[RouteInfo]:
    for context in iter_route_contexts(app.routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        operation_id = context.operation_id
        yield RouteInfo(
            path=context.path or "",
            methods=frozenset(context.methods or ()),
            operation_id=operation_id if isinstance(operation_id, str) else None,
        )


def validate_routes(app: FastAPI) -> None:
    seen: dict[str, RouteInfo] = {}
    for route in iter_api_routes(app):
        where = f"{sorted(route.methods)} {route.path}"
        if route.operation_id is None:
            raise RuntimeError(f"route {where} has no explicit operation_id")
        if not OPERATION_ID_RE.match(route.operation_id):
            raise RuntimeError(
                f"route {where}: operation_id {route.operation_id!r} does not match "
                "'<system>_<resource>_<verb>'"
            )
        if route.operation_id in seen:
            other = seen[route.operation_id]
            raise RuntimeError(
                f"duplicate operation_id {route.operation_id!r}: {where} and "
                f"{sorted(other.methods)} {other.path}"
            )
        seen[route.operation_id] = route
