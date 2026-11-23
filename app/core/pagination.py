"""Page-number pagination and strict query parameters (section 10)."""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Query, Request
from pydantic import BaseModel

from app.core.errors import field_error

MAX_PAGE_SIZE = 100


class Page[T](BaseModel):
    items: list[T]
    page: int
    page_size: int
    total: int


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
