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
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app import __version__
from app.api import docs, health
from app.api.v1 import admin, audit, me
from app.audit.middleware import AuditRequestMiddleware
from app.audit.service import AuditLogService
from app.audit.sink import AuditSink
from app.audit.writer import DbAuditSink
from app.auth import router as auth_router
from app.auth.csrf import OriginCheckMiddleware
from app.auth.dependencies import CSRF_HEADER
from app.auth.oneid import OneIdClient, build_oneid_client
from app.auth.service import build_auth_service
from app.core.db import (
    create_engine,
    create_sessionmaker,
    database_revision,
    migration_heads,
    ping_database,
)
from app.core.db_privileges import audit_privilege_problems
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.metrics import METRICS_PATH, MetricsAuditListener, metrics_endpoint
from app.core.redis import create_redis, ping_redis
from app.core.request_id import REQUEST_ID_HEADER, RequestContextMiddleware
from app.core.routes import validate_routes
from app.core.time import Clock, utcnow
from app.rbac.catalogue import sync_permission_table
from app.rbac.principal import PrincipalLoader
from app.rbac.registry import PermissionRegistry, build_registry
from app.rbac.route_check import validate_access
from app.rbac.service import AdminService
from app.settings import Settings, get_settings

OPENAPI_URL = docs.OPENAPI_URL

OPENAPI_TAGS = [
    {"name": "health", "description": "Servis holati (liveness va readiness)"},
    {
        "name": "me",
        "description": "Joriy admin va uning permission'lari (menyu shundan quriladi)",
    },
    {"name": "admin", "description": "Adminlar, rollar va permission'larni boshqarish"},
    {
        "name": "auth",
        "description": "Kirish: login + parol yoki OneID; sessiya va CSRF",
    },
    {"name": "audit", "description": "Audit log: kim, qachon, nima qildi; CSV eksport"},
]

API_DESCRIPTION = """Yagona adminka backend'i. Frontend faqat shu API bilan ishlaydi.

* **Kirish:** `POST /api/v1/auth/login` (login va parol). Sessiya `__Host-admin_session`
  HttpOnly cookie'sida turadi, frontend uni o'qimaydi.
* **CSRF:** har bir POST, PUT, PATCH va DELETE so'rovida `X-CSRF-Token` sarlavhasi.
  Token login javobida keladi, sahifa yangilansa `GET /api/v1/auth/session` beradi.
* **Ruxsat:** har bir endpoint'da `x-permissions` (kerakli permission) ko'rsatilgan.
  Ruxsat bo'lmasa `403 forbidden`.
* **Xato formati:** `{"error": {"code", "message", "request_id", "details"}}`. Mantiq
  `code`ga qarab quriladi.
* **Vaqt:** ISO 8601, UTC (`...Z`). ID'lar string.

Batafsil: repo'dagi `docs/frontend.md`.
"""

logger = get_logger(__name__)


async def check_database(engine: AsyncEngine, settings: Settings) -> None:
    """At startup:

    * the schema must be at the code's migration head, in every environment:
      an old schema only fails later, request by request, with a 500;
    * section 9: the service's DB role may only append to the audit log.
      Production refuses to start otherwise; other environments only warn
      (development usually runs everything as one role).

    If the database cannot be reached, production refuses to start and other
    environments only warn (/ready reports it)."""
    try:
        revision = await database_revision(engine)
        problems = await audit_privilege_problems(engine)
    except Exception as exc:
        if settings.is_production:
            raise RuntimeError("cannot check the database at startup") from exc
        logger.warning("database_unchecked", error=type(exc).__name__)
        return
    expected = migration_heads()
    if revision not in expected:
        raise RuntimeError(
            f"the database schema is at revision {revision or 'none'}, the code expects "
            f"{', '.join(sorted(expected))}. Run: uv run alembic upgrade head"
        )
    if not problems:
        return
    if settings.is_production:
        raise RuntimeError(
            "the application DB role (DB_USER) can modify the audit log: "
            + "; ".join(problems)
            + ". Run the migrations as DB_OWNER_USER (README, Deploy)."
        )
    logger.warning("audit_privileges_too_broad", problems=problems)


async def sync_permission_catalogue(
    db: async_sessionmaker[AsyncSession], registry: PermissionRegistry
) -> None:
    """Copies the registry to the `permissions` table (app.rbac.catalogue).
    Nothing reads that copy at runtime, so a failure only warns."""
    try:
        changes = await sync_permission_table(db, registry)
    except Exception as exc:
        logger.warning("permission_catalogue_not_synced", error=type(exc).__name__)
        return
    if changes:
        logger.info(
            "permission_catalogue_synced",
            added=changes.added,
            updated=changes.updated,
            removed=changes.removed,
        )


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
            await check_database(engine, settings)
            db = create_sessionmaker(engine)
            await sync_permission_catalogue(db, registry)
            audit = DbAuditSink(
                db, clock=clock, listeners=[MetricsAuditListener(), *audit_listeners]
            )
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
                # The same instance: one Argon2 limit per worker.
                passwords=auth_service.passwords,
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
        title="UZBMB Admin",
        version=__version__,
        description=API_DESCRIPTION,
        # FastAPI's own schema and docs routes are off: app.api.docs serves both,
        # open outside production and only with `admin:api:docs` in production.
        openapi_url=None,
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
    app.add_middleware(
        OriginCheckMiddleware,
        allowed_origin=settings.frontend_origin,
        # Swagger UI's "Try it out" (app.api.docs); never in production.
        allow_same_origin=not settings.is_production,
    )
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
    # Not an API route (no guard, not in OpenAPI): Nginx serves it on 127.0.0.1 only.
    app.add_route(METRICS_PATH, metrics_endpoint, include_in_schema=False)
    app.include_router(docs.router)
    app.mount(docs.STATIC_URL, docs.static_files(), name="swagger-ui")
    app.include_router(auth_router.router)
    app.include_router(me.router)
    app.include_router(admin.router)
    app.include_router(audit.router)
    docs.install_openapi(app)
    return app
