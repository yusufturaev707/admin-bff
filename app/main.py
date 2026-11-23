"""Application factory.

Development:  uv run uvicorn --factory app.main:create_app --reload
Production:   gunicorn -c deploy/gunicorn.conf.py "app.main:create_app()"
"""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import partial

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from app import __version__
from app.api import health
from app.audit.sink import AuditSink, LogAuditSink
from app.auth import router as auth_router
from app.auth.csrf import OriginCheckMiddleware
from app.auth.dependencies import CSRF_HEADER
from app.auth.oneid import OneIdClient, build_oneid_client
from app.auth.service import build_auth_service
from app.core.db import create_engine, create_sessionmaker, ping_database
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.redis import create_redis, ping_redis
from app.core.request_id import REQUEST_ID_HEADER, RequestContextMiddleware
from app.core.routes import validate_routes
from app.core.time import Clock, utcnow
from app.settings import Settings, get_settings

OPENAPI_URL = "/api/v1/openapi.json"

OPENAPI_TAGS = [
    {"name": "health", "description": "Servis holati (liveness va readiness)"},
    {
        "name": "auth",
        "description": "Kirish: login + parol yoki OneID, keyin TOTP; sessiya, CSRF, step-up",
    },
]

logger = get_logger(__name__)


def require_explicit_operation_id(route: APIRoute) -> str:
    """operationIds are part of the frontend contract and must never change
    implicitly (e.g. when a function is renamed), so every route sets one."""
    raise RuntimeError(
        f"route {sorted(route.methods or ())} {route.path} has no explicit operation_id "
        "(expected '<system>_<resource>_<verb>')"
    )


def _lifespan(
    settings: Settings,
    *,
    clock: Clock,
    audit_sink: AuditSink | None,
    oneid_client: OneIdClient | None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Runs after every router is included: a bad route table stops startup.
        validate_routes(app)
        # OneID stays off unless enabled; enabled without a client, startup stops.
        oneid = (oneid_client or build_oneid_client(settings)) if settings.oneid_enabled else None
        engine = create_engine(settings)
        redis = create_redis(settings)
        try:
            app.state.auth_service = build_auth_service(
                settings,
                create_sessionmaker(engine),
                redis,
                clock=clock,
                audit=audit_sink or LogAuditSink(),
                oneid_client=oneid,
            )
            app.state.readiness_checks = {
                "db": partial(ping_database, engine),
                "redis": partial(ping_redis, redis),
            }
            logger.info("startup", version=__version__, env=settings.app_env)
            yield
        finally:
            if oneid is not None:
                await oneid.aclose()
            await redis.aclose()
            await engine.dispose()
            logger.info("shutdown")

    return lifespan


def create_app(
    settings: Settings | None = None,
    *,
    clock: Clock = utcnow,
    audit_sink: AuditSink | None = None,
    oneid_client: OneIdClient | None = None,
) -> FastAPI:
    """`clock`, `audit_sink` and `oneid_client` are replaced only in tests."""
    settings = settings or get_settings()
    configure_logging(settings)

    app = FastAPI(
        title="UZBMB Admin BFF",
        version=__version__,
        description="Yagona adminka backend'i. Frontend faqat shu API bilan ishlaydi.",
        # The schema endpoint is closed in production; Phase 2 serves it (and
        # locally hosted Swagger UI) only to admins with `admin:api:docs`.
        openapi_url=None if settings.is_production else OPENAPI_URL,
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
        openapi_tags=OPENAPI_TAGS,
        generate_unique_id_function=require_explicit_operation_id,
        lifespan=_lifespan(settings, clock=clock, audit_sink=audit_sink, oneid_client=oneid_client),
        debug=False,
    )
    app.state.settings = settings
    app.state.clock = clock

    install_exception_handlers(app)

    # Starlette wraps middleware in reverse order: the last added is the
    # outermost. Order from the outside: request id + access log, CORS (so even
    # rejected requests get CORS headers), Origin check (CSRF), the app.
    app.add_middleware(OriginCheckMiddleware, allowed_origin=settings.frontend_origin)
    if settings.frontend_origin is not None:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings.frontend_origin],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=[
                "Content-Type",
                CSRF_HEADER,
                REQUEST_ID_HEADER,
                "Idempotency-Key",
                "Last-Event-ID",
            ],
            expose_headers=[REQUEST_ID_HEADER],
            max_age=600,
        )
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    return app
