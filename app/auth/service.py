"""Auth use cases (section 6). Routers stay thin: every decision is made here.

Sign-in is one step: username and password, or OneID. TOTP was removed at the
owner's request (2026-11-23); with it went the mfa_token, recovery codes and
step-up. A new admin's first session can only change the password.
"""

import hmac
import uuid
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth.crypto import new_token, sha256_hex
from app.auth.lockout import LoginLimiter
from app.auth.models import AdminUser, AuthMethod, normalize_username
from app.auth.oneid import OneIdClient
from app.auth.passwords import PasswordPolicyError, PasswordService, check_password_policy
from app.auth.providers import (
    AuthFailedError,
    AuthProvider,
    LocalAuthProvider,
    OneIdAuthProvider,
    OneIdCredentials,
    PasswordCredentials,
)
from app.auth.sessions import PendingStep, SessionData, SessionStore
from app.auth.tickets import OneTimeStore
from app.core.errors import AppError, ErrorCode, field_error
from app.core.logging import get_logger
from app.core.ratelimit import FixedWindowLimiter
from app.core.time import Clock
from app.settings import Settings

INVALID_CREDENTIALS = "Login yoki parol noto'g'ri"
LOCKED = "Juda ko'p muvaffaqiyatsiz urinish. Keyinroq qayta urinib ko'ring"

ONEID_STATE_TTL_S = 5 * 60

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RequestMeta:
    ip: str
    user_agent: str
    request_id: str | None


@dataclass(frozen=True, slots=True)
class SessionStarted:
    session_id: str
    session: SessionData


class OneIdLoginError(Exception):
    """Any OneID callback failure; the browser gets one generic error page."""


def _pending_steps(user: AdminUser) -> list[PendingStep]:
    # A OneID-only admin has no password to change.
    if user.must_change_password and user.password_hash is not None:
        return [PendingStep.PASSWORD_CHANGE]
    return []


class AuthService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: async_sessionmaker[AsyncSession],
        passwords: PasswordService,
        sessions: SessionStore,
        one_time: OneTimeStore,
        limiter: LoginLimiter,
        audit: AuditSink,
        clock: Clock,
        request_limiter: FixedWindowLimiter | None = None,
        oneid_client: OneIdClient | None = None,
    ) -> None:
        self._settings = settings
        self._db = db
        # Shared with AdminService (app.main), so one worker has one Argon2 limit.
        self.passwords = passwords
        self.sessions = sessions
        self._one_time = one_time
        self.limiter = limiter
        # Per-session request rate (section 11), checked by current_session.
        self.request_limiter = request_limiter
        self._audit_sink = audit
        self._clock = clock
        self._oneid_client = oneid_client
        self._providers: dict[AuthMethod, AuthProvider[Any]] = {
            AuthMethod.PASSWORD: LocalAuthProvider(passwords),
        }
        self._oneid: OneIdAuthProvider | None = None
        if oneid_client is not None:
            self._oneid = OneIdAuthProvider(oneid_client, settings.pinfl_key())
            self._providers[AuthMethod.ONEID] = self._oneid

    # --- helpers -----------------------------------------------------------

    async def _audit(
        self,
        action: str,
        outcome: AuditOutcome,
        meta: RequestMeta,
        *,
        user: AdminUser | None = None,
        username: str | None = None,
        session: SessionData | None = None,
        **details: Any,
    ) -> None:
        """`username` is what was typed into the login form. It is recorded in
        clear text only together with a real account; otherwise only a short
        hash, because people sometimes type their password into that field."""
        actor_id: uuid.UUID | None = user.id if user else (session.user_id if session else None)
        actor_username = user.username if user else (session.username if session else None)
        if actor_username is None and username:
            details["attempted_username_sha256"] = sha256_hex(username)[:16]
        await self._audit_sink.write(
            AuditEvent(
                action=action,
                outcome=outcome,
                actor_id=actor_id,
                actor_username=actor_username,
                actor_ip=meta.ip,
                user_agent=meta.user_agent,
                session_hash=session.key if session else None,
                request_id=meta.request_id,
                details=details,
            )
        )

    async def _ensure_not_locked(self, username: str | None, meta: RequestMeta) -> None:
        retry_after = await self.limiter.retry_after(username, meta.ip)
        if retry_after is not None:
            await self._audit(
                "auth.login", AuditOutcome.DENIED, meta, username=username, reason="locked"
            )
            raise AppError(
                ErrorCode.RATE_LIMITED, LOCKED, headers={"Retry-After": str(retry_after)}
            )

    async def _register_failure(self, username: str | None, meta: RequestMeta) -> None:
        for rule in await self.limiter.record_failure(username, meta.ip):
            await self._audit(
                "auth.lockout",
                AuditOutcome.DENIED,
                meta,
                username=username if rule.name == "user" else None,
                rule=rule.name,
                lock_s=rule.lock_s,
            )
            # TODO(phase-8): also raise an in-app alert (section 10.1).
            logger.warning("auth_lockout", rule=rule.name, ip=meta.ip)

    async def _start_session(
        self, user: AdminUser, method: AuthMethod, meta: RequestMeta, step: str
    ) -> SessionStarted:
        """Always a new session id (session fixation protection)."""
        session_id, session = await self.sessions.create(
            user_id=user.id,
            username=user.username,
            auth_method=method,
            ip=meta.ip,
            user_agent=meta.user_agent,
            pending=_pending_steps(user),
            perm_version=user.perm_version,
        )
        await self._audit(
            "auth.login", AuditOutcome.SUCCESS, meta, user=user, session=session, step=step
        )
        return SessionStarted(session_id, session)

    # --- login ---------------------------------------------------------------

    async def login_password(
        self, username: str, password: str, meta: RequestMeta
    ) -> SessionStarted:
        normalized = normalize_username(username)
        await self._ensure_not_locked(normalized, meta)
        failure: AuthFailedError | None = None
        async with self._db() as db, db.begin():
            try:
                user = await self._providers[AuthMethod.PASSWORD].authenticate(
                    db, PasswordCredentials(username, password)
                )
            except AuthFailedError as exc:
                failure = exc
            else:
                user.last_login_at = self._clock()
        if failure is not None:
            await self._register_failure(normalized, meta)
            await self._audit(
                "auth.login",
                AuditOutcome.DENIED,
                meta,
                user=failure.user,
                username=normalized,
                step="password",
                reason=failure.reason,
            )
            raise AppError(ErrorCode.NOT_AUTHENTICATED, INVALID_CREDENTIALS)
        if normalized is not None:
            await self.limiter.reset_user(normalized)
        return await self._start_session(user, AuthMethod.PASSWORD, meta, step="password")

    async def logout(self, session: SessionData, meta: RequestMeta) -> None:
        await self.sessions.delete(session)
        await self._audit("auth.logout", AuditOutcome.SUCCESS, meta, session=session)

    # --- sessions ----------------------------------------------------------

    async def list_sessions(self, session: SessionData) -> list[SessionData]:
        return await self.sessions.list_for_user(session.user_id)

    async def revoke_session(
        self, session: SessionData, target_key: str, meta: RequestMeta
    ) -> bool:
        """Ends one of the admin's own sessions. Returns True if it was the current one."""
        mine = {s.key: s for s in await self.sessions.list_for_user(session.user_id)}
        target = mine.get(target_key)
        if target is None:
            raise AppError(ErrorCode.NOT_FOUND)
        await self.sessions.delete(target)
        await self._audit(
            "auth.session.revoke", AuditOutcome.SUCCESS, meta, session=session, target=target.key
        )
        return target.key == session.key

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> int:
        """Used on password change, block and role change."""
        return await self.sessions.delete_all_for_user(user_id)

    async def _load_user(self, db: AsyncSession, session: SessionData) -> AdminUser:
        user = await db.get(AdminUser, session.user_id)
        if user is None or not user.is_active:
            await self.sessions.delete(session)
            raise AppError(ErrorCode.SESSION_EXPIRED)
        return user

    # --- password ------------------------------------------------------------

    async def change_password(
        self, session: SessionData, old_password: str, new_password: str, meta: RequestMeta
    ) -> None:
        """Needs the current password. Ends every session of the admin."""
        wrong_password = False
        async with self._db() as db, db.begin():
            user = await self._load_user(db, session)
            if user.password_hash is None:
                raise AppError(ErrorCode.CONFLICT, "Bu hisob uchun parol o'rnatilmagan")
            # The policy is checked first: it needs no secret.
            try:
                check_password_policy(new_password, username=user.username)
            except PasswordPolicyError as exc:
                raise field_error(("body", "new_password"), exc.reason, exc.message) from exc
            if not await self.passwords.verify(user.password_hash, old_password):
                wrong_password = True
            elif await self.passwords.verify(user.password_hash, new_password):
                raise field_error(
                    ("body", "new_password"), "password_reused", "Yangi parol eskisidan farq qilsin"
                )
            else:
                user.password_hash = await self.passwords.hash(new_password)
                user.password_changed_at = self._clock()
                user.must_change_password = False
        if wrong_password:
            await self._register_failure(session.username, meta)
            await self._audit(
                "auth.password.change",
                AuditOutcome.DENIED,
                meta,
                session=session,
                reason="old_password",
            )
            raise field_error(("body", "old_password"), "invalid_password", "Joriy parol noto'g'ri")
        revoked = await self.revoke_all_sessions(session.user_id)
        await self._audit(
            "auth.password.change",
            AuditOutcome.SUCCESS,
            meta,
            session=session,
            revoked_sessions=revoked,
        )

    # --- OneID (template) ----------------------------------------------------

    @property
    def oneid_enabled(self) -> bool:
        return self._oneid is not None

    async def oneid_start(self) -> tuple[str, str]:
        """Returns (OneID login URL, state). The state is also bound to the browser
        with a cookie, so a callback started in another browser is rejected."""
        if self._oneid_client is None:
            raise AppError(ErrorCode.NOT_FOUND)
        state = new_token()
        await self._one_time.put("oneid_state", sha256_hex(state), b"1", ttl_s=ONEID_STATE_TTL_S)
        return self._oneid_client.authorization_url(state), state

    async def oneid_callback(
        self, code: str | None, state: str | None, cookie_state: str | None, meta: RequestMeta
    ) -> SessionStarted:
        if self._oneid is None:
            raise AppError(ErrorCode.NOT_FOUND)
        # Bytes comparison: query values may contain non-ASCII text.
        state_ok = (
            bool(
                code
                and state
                and cookie_state
                and hmac.compare_digest(state.encode(), cookie_state.encode())
            )
            and (await self._one_time.take("oneid_state", sha256_hex(state or ""))) is not None
        )
        if not state_ok or code is None:
            await self._audit(
                "auth.login", AuditOutcome.DENIED, meta, step="oneid", reason="bad_state"
            )
            raise OneIdLoginError
        try:
            await self._ensure_not_locked(None, meta)
        except AppError as exc:
            raise OneIdLoginError from exc
        failure: AuthFailedError | None = None
        async with self._db() as db, db.begin():
            try:
                user = await self._oneid.authenticate(db, OneIdCredentials(code))
            except AuthFailedError as exc:
                failure = exc
            else:
                user.last_login_at = self._clock()
        if failure is not None:
            await self._register_failure(None, meta)
            await self._audit(
                "auth.login",
                AuditOutcome.DENIED,
                meta,
                user=failure.user,
                step="oneid",
                reason=failure.reason,
            )
            raise OneIdLoginError
        return await self._start_session(user, AuthMethod.ONEID, meta, step="oneid")


def build_auth_service(
    settings: Settings,
    db: async_sessionmaker[AsyncSession],
    redis: Redis,
    *,
    clock: Clock,
    audit: AuditSink,
    oneid_client: OneIdClient | None,
) -> AuthService:
    prefix = settings.redis_key_prefix
    return AuthService(
        settings=settings,
        db=db,
        passwords=PasswordService(settings),
        sessions=SessionStore(
            redis,
            prefix=prefix,
            idle_timeout_s=settings.session_idle_timeout_s,
            absolute_timeout_s=settings.session_absolute_timeout_s,
            clock=clock,
        ),
        one_time=OneTimeStore(redis, prefix=prefix),
        limiter=LoginLimiter(redis, prefix=prefix),
        audit=audit,
        clock=clock,
        request_limiter=FixedWindowLimiter(
            redis,
            prefix=prefix,
            name="session_requests",
            limit=settings.session_requests_per_minute,
            window_s=60,
        ),
        oneid_client=oneid_client,
    )
