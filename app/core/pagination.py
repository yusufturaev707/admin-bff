"""Pagination and strict query parameters (section 10).

* page numbers: `?page=1&page_size=50` -> `Page` (`total` included);
* cursors, for large tables such as the audit log: `?cursor=&limit=` ->
  `CursorPage` with `next_cursor` (null on the last page). A cursor is opaque
  to the client; it encodes the id of the last item of the previous page.
"""

import base64
import binascii
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field

from app.core.errors import field_error

MAX_PAGE_SIZE = 100
_CURSOR_PREFIX = "v1:"


class Page[T](BaseModel):
    items: list[T]
    page: int
    page_size: int
    total: int


class CursorPage[T](BaseModel):
    items: list[T]
    next_cursor: str | None = Field(description="Keyingi sahifa uchun `cursor`; oxirgisida null")


def encode_cursor(last_id: int) -> str:
    return base64.urlsafe_b64encode(f"{_CURSOR_PREFIX}{last_id}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """Raises a 422 for anything that is not a cursor issued by `encode_cursor`."""
    error = field_error(("query", "cursor"), "invalid_cursor", "Cursor noto'g'ri")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise error from exc
    value = raw.removeprefix(_CURSOR_PREFIX)
    if raw == value or not value.isdigit() or len(value) > 19:
        raise error
    return int(value)


class PageParams(BaseModel):
    page: int
    page_size: int

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


async def page_params(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
) -> PageParams:
    return PageParams(page=page, page_size=page_size)


PageParamsDep = Annotated[PageParams, Depends(page_params)]


def known_query_params(*names: str) -> Callable[[Request], Awaitable[None]]:
    """422 for an unknown query parameter instead of silently ignoring it, so a
    typo in a filter never returns unfiltered data."""
    allowed = frozenset(names)

    async def dependency(request: Request) -> None:
        unknown = sorted(set(request.query_params) - allowed)
        if unknown:
            raise field_error(("query", unknown[0]), "unknown_parameter", "Noma'lum parametr")

    return dependency
