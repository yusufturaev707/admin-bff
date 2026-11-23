"""Application factory.

Development:  uv run uvicorn --factory app.main:create_app --reload
Production:   gunicorn -c deploy/gunicorn.conf.py "app.main:create_app()"
"""

from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from functools import partial

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncEngine

from app import __version__
from app.api import health
from app.api.v1 import admin, audit, me
from app.audit.middleware import AuditRequestMiddleware
from app.audit.service import AuditLogService
from app.audit.sink import AuditSink
from app.audit.writer import DbAuditSink
from app.auth import router as auth_router
from app.auth.csrf import OriginCheckMiddleware
from app.auth.dependencies import CSRF_HEADER
from app.auth.oneid import OneIdClient, build_oneid_client
from app.auth.passwords import PasswordService
from app.auth.service import build_auth_service
from app.core.db import create_engine, create_sessionmaker, ping_database
from app.core.db_privileges import audit_privilege_problems
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.redis import create_redis, ping_redis
from app.core.request_id import REQUEST_ID_HEADER, RequestContextMiddleware
from app.core.routes import validate_routes
from app.core.time import Clock, utcnow
from app.rbac.principal import PrincipalLoader
from app.rbac.registry import PermissionRegistry, build_registry
from app.rbac.route_check import validate_access
from app.rbac.service import AdminService
from app.settings import Settings, get_settings

OPENAPI_URL = "/api/v1/openapi.json"

OPENAPI_TAGS = [
    {"name": "health", "description": "Servis holati (liveness va readiness)"},
    {
        "name": "me",
        "description": "Joriy admin: permission'lar va hududlar (menyu shundan quriladi)",
    },
    {"name": "admin", "description": "Adminlar, rollar va permission'larni boshqarish"},
    {
        "name": "auth",
        "description": "Kirish: login + parol yoki OneID, keyin TOTP; sessiya, CSRF, step-up",
    },
    {"name": "audit", "description": "Audit log: kim, qachon, nima qildi; CSV eksport"},
]

logger = get_logger(__name__)


async def check_audit_privileges(engine: AsyncEngine, settings: Settings) -> None:
    """Section 9: the service's DB role may only append to the audit log.
    Production refuses to start otherwise; other environments only warn
    (development usually runs everything as one role)."""
    try:
        problems = await audit_privilege_problems(engine)
    except Exception as exc:
        if settings.is_production:
            raise RuntimeError("cannot check the DB privileges of the audit tables") from exc
        logger.warning("audit_privileges_unchecked", error=type(exc).__name__)
        return
    if not problems:
        return
    if settings.is_production:
        raise RuntimeError(
            "the application DB role (DB_USER) can modify the audit log: "
            + "; ".join(problems)
            + ". Run the migrations as DB_OWNER_USER (README, Deploy)."
        )
    logger.warning("audit_privileges_too_broad", problems=problems)


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
    audit_listeners: Sequence[AuditSink],
    oneid_client: OneIdClient | None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Runs after every router is included: a bad route table stops startup.
        validate_routes(app)
        registry: PermissionRegistry = app.state.registry
        # Deny-by-default (section 7). Tests may add their own public test routes.
        validate_access(
            app, registry, extra_public=getattr(app.state, "extra_public_paths", frozenset())
        )
        # OneID stays off unless enabled; enabled without a client, startup stops.
        oneid = (oneid_client or build_oneid_client(settings)) if settings.oneid_enabled else None
        engine = create_engine(settings)
        redis = create_redis(settings)
        try:
            await check_audit_privileges(engine, settings)
            db = create_sessionmaker(engine)
            audit = DbAuditSink(db, clock=clock, listeners=audit_listeners)
            auth_service = build_auth_service(
                settings, db, redis, clock=clock, audit=audit, oneid_client=oneid
            )
            loader = PrincipalLoader(db, redis, prefix=settings.redis_key_prefix)
            app.state.audit_sink = audit
            app.state.auth_service = auth_service
            app.state.principal_loader = loader
            app.state.admin_service = AdminService(
                settings=settings,
                db=db,
                registry=registry,
                loader=loader,
                sessions=auth_service.sessions,
                limiter=auth_service.limiter,
                passwords=PasswordService(settings),
                audit=audit,
            )
            app.state.audit_log_service = AuditLogService(
                db, redis=redis, prefix=settings.redis_key_prefix, audit=audit
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
    audit_listeners: Sequence[AuditSink] = (),
    oneid_client: OneIdClient | None = None,
) -> FastAPI:
    """`clock` and `oneid_client` are replaced only in tests. `audit_listeners`
    receive a copy of every stored audit event (tests; in-app alerts later)."""
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
        lifespan=_lifespan(
            settings, clock=clock, audit_listeners=audit_listeners, oneid_client=oneid_client
        ),
        debug=False,
    )
    app.state.settings = settings
    app.state.clock = clock
    app.state.registry = build_registry()

    install_exception_handlers(app)

    # Starlette wraps middleware in reverse order: the last added is the
    # outermost. Order from the outside: request id + access log, request-level
    # audit (sees every status, CSRF rejections included), CORS (so even
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
    app.add_middleware(AuditRequestMiddleware)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(me.router)
    app.include_router(admin.router)
    app.include_router(audit.router)
    return app
