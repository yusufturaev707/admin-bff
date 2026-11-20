"""Liveness and readiness probes. Both are public (section 7)."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict

from app.core.logging import get_logger

ReadinessCheck = Callable[[], Awaitable[None]]

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


class HealthResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"status": "ok"}})

    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"status": "ok", "checks": {"db": "ok", "redis": "ok"}},
        }
    )

    status: Literal["ok", "unavailable"]
    checks: dict[str, Literal["ok", "error"]]


def get_readiness_checks(request: Request) -> Mapping[str, ReadinessCheck]:
    checks: Mapping[str, ReadinessCheck] = request.app.state.readiness_checks
    return checks


@router.get(
    "/health",
    operation_id="core_health_get",
    summary="Liveness: jarayon ishlayaptimi",
    response_model=HealthResponse,
)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/ready",
    operation_id="core_readiness_get",
    summary="Readiness: DB va Redis ishlayaptimi",
    response_model=ReadinessResponse,
    responses={
        503: {"model": ReadinessResponse, "description": "Bog'liqliklardan biri ishlamayapti"}
    },
)
async def ready(
    request: Request,
    response: Response,
    checks: Annotated[Mapping[str, ReadinessCheck], Depends(get_readiness_checks)],
) -> ReadinessResponse:
    timeout_s: float = request.app.state.settings.ready_timeout_s

    async def run(name: str, check: ReadinessCheck) -> tuple[str, bool]:
        try:
            async with asyncio.timeout(timeout_s):
                await check()
        except Exception as exc:
            # Only the exception type is logged: messages may contain hostnames.
            logger.warning("readiness_check_failed", check=name, error=type(exc).__name__)
            return name, False
        return name, True

    results = await asyncio.gather(*(run(name, check) for name, check in checks.items()))
    statuses: dict[str, Literal["ok", "error"]] = {
        name: "ok" if ok else "error" for name, ok in results
    }
    all_ok = all(ok for _, ok in results)
    if not all_ok:
        response.status_code = 503
    return ReadinessResponse(status="ok" if all_ok else "unavailable", checks=statuses)
