"""Auth use cases (section 6). Routers stay thin: every decision is made here."""

import hmac
import uuid
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit.sink import AuditEvent, AuditOutcome, AuditSink
from app.auth import totp
from app.auth.crypto import DecryptionError, SecretBox, new_token, sha256_hex
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
from app.auth.second_factor import RecoveryFactor, SecondFactor, SecondFactorVerifier, TotpFactor
from app.auth.sessions import PendingStep, SessionData, SessionStore
from app.auth.tickets import MfaTokenStore, OneTimeStore
from app.core.errors import AppError, ErrorCode, field_error
from app.core.logging import get_logger
from app.core.ratelimit import FixedWindowLimiter
from app.core.time import Clock
from app.settings import Settings

INVALID_CREDENTIALS = "Login yoki parol noto'g'ri"
INVALID_CODE = "Kod noto'g'ri yoki muddati o'tgan"
LOCKED = "Juda ko'p muvaffaqiyatsiz urinish. Keyinroq qayta urinib ko'ring"
LOGIN_EXPIRED = "Kirish muddati tugadi, qaytadan kiring"

TOTP_ENROLL_TTL_S = 10 * 60
ONEID_STATE_TTL_S = 5 * 60

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class RequestMeta:
    ip: str
    user_agent: str
    request_id: str | None


@dataclass(frozen=True, slots=True)
class MfaRequired:
    """Primary factor accepted; the client continues with POST /auth/mfa."""

    mfa_token: str


@dataclass(frozen=True, slots=True)
class SessionStarted:
    session_id: str
    session: SessionData


type LoginResult = MfaRequired | SessionStarted


@dataclass(frozen=True, slots=True)
class TotpEnrollment:
    secret: str
    otpauth_uri: str


@dataclass(frozen=True, slots=True)
class TotpConfirmed:
    started: SessionStarted
    recovery_codes: list[str]


class OneIdLoginError(Exception):
    """Any OneID callback failure; the browser gets one generic error page."""


def _pending_steps(user: AdminUser, *, totp_ready: bool) -> list[PendingStep]:
    steps: list[PendingStep] = []
    if not totp_ready:
        steps.append(PendingStep.TOTP_ENROLLMENT)
    # A OneID-only admin has no password to change.
    if user.must_change_password and user.password_hash is not None:
        steps.append(PendingStep.PASSWORD_CHANGE)
    return steps


class AuthService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: async_sessionmaker[AsyncSession],
        passwords: PasswordService,
        second_factor: SecondFactorVerifier,
        sessions: SessionStore,
        mfa_tokens: MfaTokenStore,
        one_time: OneTimeStore,
        limiter: LoginLimiter,
        audit: AuditSink,
        clock: Clock,
        request_limiter: FixedWindowLimiter | None = None,
        oneid_client: OneIdClient | None = None,
    ) -> None:
        self._settings = settings
        self._db = db
        self._passwords = passwords
        self._second_factor = second_factor
        self.sessions = sessions
        self._mfa_tokens = mfa_tokens
        self._one_time = one_time
        self.limiter = limiter
        # Per-session request rate (section 11), checked by current_session.
        self.request_limiter = request_limiter
        self._audit_sink = audit
        self._clock = clock
        self._oneid_client = oneid_client
        self._providers: dict[AuthMethod, AuthProvider[Any]] = {
            AuthMethod.PASSWORD: LocalAuthProvider(second_factor, passwords),
        }
        self._oneid: OneIdAuthProvider | None = None
        if oneid_client is not None:
            self._oneid = OneIdAuthProvider(second_factor, oneid_client, settings.pinfl_key())
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
        self, user: AdminUser, method: AuthMethod, meta: RequestMeta, *, mfa_done: bool
    ) -> SessionStarted:
        now = self._clock()
        session_id, session = await self.sessions.create(
            user_id=user.id,
            username=user.username,
            auth_method=method,
            ip=meta.ip,
            user_agent=meta.user_agent,
            mfa_at=now if mfa_done else None,
            pending=_pending_steps(user, totp_ready=user.totp_enabled),
            perm_version=user.perm_version,
        )
        return SessionStarted(session_id, session)

    async def _after_primary_factor(
        self, user: AdminUser, method: AuthMethod, meta: RequestMeta
    ) -> LoginResult:
        if user.totp_enabled:
            token = await self._mfa_tokens.issue(
                user_id=user.id, username=user.username, method=method
            )
            return MfaRequired(token)
        # First sign-in: no TOTP yet. A restricted session that can only enroll
        # TOTP (and then change the password) is the only thing granted.
        started = await self._start_session(user, method, meta, mfa_done=False)
        await self._audit(
            "auth.login",
            AuditOutcome.SUCCESS,
            meta,
            user=user,
            session=started.session,
            step="setup",
        )
        return started

    # --- login ---------------------------------------------------------------

    async def login_password(self, username: str, password: str, meta: RequestMeta) -> LoginResult:
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
        await self._audit("auth.login", AuditOutcome.SUCCESS, meta, user=user, step="password")
        return await self._after_primary_factor(user, AuthMethod.PASSWORD, meta)

    async def complete_mfa(
        self, mfa_token: str, factor: SecondFactor, meta: RequestMeta
    ) -> SessionStarted:
        ticket = await self._mfa_tokens.get(mfa_token)
        if ticket is None:
            raise AppError(ErrorCode.SESSION_EXPIRED, LOGIN_EXPIRED)
        await self._ensure_not_locked(ticket.username, meta)
        factor_name = "recovery_code" if isinstance(factor, RecoveryFactor) else "code"
        async with self._db() as db, db.begin():
            user = await db.get(AdminUser, ticket.user_id)
            if user is None or not user.is_active or not user.allows(ticket.method):
                await self._mfa_tokens.consume(mfa_token)
                raise AppError(ErrorCode.SESSION_EXPIRED, LOGIN_EXPIRED)
            ok = await self._providers[ticket.method].verify_second_factor(db, user, factor)
            if ok:
                user.last_login_at = self._clock()
            remaining = (
                await self._second_factor.remaining_recovery_codes(db, user.id)
                if ok and factor_name == "recovery_code"
                else None
            )
        if not ok:
            await self._mfa_tokens.record_failure(mfa_token)
            await self._register_failure(ticket.username, meta)
            await self._audit(
                "auth.login", AuditOutcome.DENIED, meta, user=user, step="mfa", factor=factor_name
            )
            raise field_error(("body", factor_name), "invalid_code", INVALID_CODE)
        if not await self._mfa_tokens.consume(mfa_token):
            # Another request finished this login first.
            raise AppError(ErrorCode.SESSION_EXPIRED, LOGIN_EXPIRED)
        await self.limiter.reset_user(ticket.username)
        started = await self._start_session(user, ticket.method, meta, mfa_done=True)
        await self._audit(
            "auth.login",
            AuditOutcome.SUCCESS,
            meta,
            user=user,
            session=started.session,
            step="mfa",
            factor=factor_name,
            method=ticket.method.value,
        )
        if remaining is not None:
            await self._audit(
                "auth.recovery_code.use",
                AuditOutcome.SUCCESS,
                meta,
                user=user,
                session=started.session,
                remaining=remaining,
            )
        return started

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
        """Used on password change, block and role change (Phase 2)."""
        return await self.sessions.delete_all_for_user(user_id)

    # --- TOTP enrollment ---------------------------------------------------

    async def _load_user(self, db: AsyncSession, session: SessionData) -> AdminUser:
        user = await db.get(AdminUser, session.user_id)
        if user is None or not user.is_active:
            await self.sessions.delete(session)
            raise AppError(ErrorCode.SESSION_EXPIRED)
        return user

    async def enroll_totp(self, session: SessionData, meta: RequestMeta) -> TotpEnrollment:
        async with self._db() as db:
            user = await self._load_user(db, session)
        if user.totp_enabled:
            raise AppError(ErrorCode.CONFLICT, "TOTP allaqachon ulangan")
        secret = totp.new_secret()
        await self._one_time.put(
            "totp_enroll",
            session.key,
            self._second_factor.encrypt_secret(user.id, secret),
            ttl_s=TOTP_ENROLL_TTL_S,
        )
        await self._audit(
            "auth.totp.enroll", AuditOutcome.SUCCESS, meta, session=session, step="start"
        )
        return TotpEnrollment(
            secret=secret,
            otpauth_uri=totp.provisioning_uri(
                secret, username=user.username, issuer=self._settings.totp_issuer
            ),
        )

    async def confirm_totp(
        self, session: SessionData, code: str, meta: RequestMeta
    ) -> TotpConfirmed:
        blob = await self._one_time.get("totp_enroll", session.key)
        if blob is None:
            raise AppError(ErrorCode.CONFLICT, "Avval TOTP ulashni boshlang")
        try:
            secret = self._second_factor.decrypt_secret(session.user_id, blob)
        except DecryptionError as exc:
            raise AppError(ErrorCode.CONFLICT, "Avval TOTP ulashni boshlang") from exc
        step = totp.match_timecode(secret, code, self._clock())
        if step is None:
            raise field_error(("body", "code"), "invalid_code", INVALID_CODE)
        async with self._db() as db, db.begin():
            user = await self._load_user(db, session)
            if user.totp_enabled:
                raise AppError(ErrorCode.CONFLICT, "TOTP allaqachon ulangan")
            user.totp_secret_enc = blob
            user.totp_confirmed_at = self._clock()
            user.totp_last_timecode = step
            recovery_codes = await self._second_factor.replace_recovery_codes(db, user.id)
        await self._one_time.delete("totp_enroll", session.key)
        # Privilege change: the session gets a new id (and CSRF token).
        session_id, rotated = await self.sessions.rotate(
            session,
            mfa_at=self._clock(),
            pending=tuple(p for p in session.pending if p is not PendingStep.TOTP_ENROLLMENT),
        )
        await self._audit(
            "auth.totp.enroll", AuditOutcome.SUCCESS, meta, session=rotated, step="confirm"
        )
        return TotpConfirmed(SessionStarted(session_id, rotated), recovery_codes)

    # --- password and step-up ---------------------------------------------

    async def change_password(
        self,
        session: SessionData,
        old_password: str,
        new_password: str,
        code: str,
        meta: RequestMeta,
    ) -> None:
        """Needs the current password and a TOTP code. Ends every session of the admin."""
        failure: str | None = None
        async with self._db() as db, db.begin():
            user = await self._load_user(db, session)
            if not user.totp_enabled:
                raise AppError(
                    ErrorCode.FORBIDDEN,
                    "Avval TOTP'ni ulang",
                    details={"pending": [PendingStep.TOTP_ENROLLMENT.value]},
                )
            if user.password_hash is None:
                raise AppError(ErrorCode.CONFLICT, "Bu hisob uchun parol o'rnatilmagan")
            # The policy is checked first: it needs no secret and must not burn a TOTP code.
            try:
                check_password_policy(new_password, username=user.username)
            except PasswordPolicyError as exc:
                raise field_error(("body", "new_password"), exc.reason, exc.message) from exc
            if not await self._passwords.verify(user.password_hash, old_password):
                failure = "old_password"
            elif not await self._second_factor.verify(db, user, TotpFactor(code)):
                failure = "code"
            elif await self._passwords.verify(user.password_hash, new_password):
                raise field_error(
                    ("body", "new_password"), "password_reused", "Yangi parol eskisidan farq qilsin"
                )
            else:
                user.password_hash = await self._passwords.hash(new_password)
                user.password_changed_at = self._clock()
                user.must_change_password = False
        if failure is not None:
            await self._register_failure(session.username, meta)
            await self._audit(
                "auth.password.change", AuditOutcome.DENIED, meta, session=session, reason=failure
            )
            message = "Joriy parol noto'g'ri" if failure == "old_password" else INVALID_CODE
            error_type = "invalid_password" if failure == "old_password" else "invalid_code"
            raise field_error(("body", failure), error_type, message)
        revoked = await self.revoke_all_sessions(session.user_id)
        await self._audit(
            "auth.password.change",
            AuditOutcome.SUCCESS,
            meta,
            session=session,
            revoked_sessions=revoked,
        )

    async def step_up(self, session: SessionData, code: str, meta: RequestMeta) -> SessionData:
        await self._ensure_not_locked(session.username, meta)
        async with self._db() as db, db.begin():
            user = await self._load_user(db, session)
            ok = await self._second_factor.verify(db, user, TotpFactor(code))
        if not ok:
            await self._register_failure(session.username, meta)
            await self._audit("auth.step_up", AuditOutcome.DENIED, meta, session=session)
            raise field_error(("body", "code"), "invalid_code", INVALID_CODE)
        updated = await self.sessions.update(session, mfa_at=self._clock())
        if updated is None:
            raise AppError(ErrorCode.SESSION_EXPIRED)
        await self._audit("auth.step_up", AuditOutcome.SUCCESS, meta, session=updated)
        return updated

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
    ) -> LoginResult:
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
        await self._audit("auth.login", AuditOutcome.SUCCESS, meta, user=user, step="oneid")
        return await self._after_primary_factor(user, AuthMethod.ONEID, meta)


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
    passwords = PasswordService(settings)
    return AuthService(
        settings=settings,
        db=db,
        passwords=passwords,
        second_factor=SecondFactorVerifier(
            box=SecretBox(settings.totp_key(), previous=settings.totp_previous_keys()),
            passwords=passwords,
            clock=clock,
        ),
        sessions=SessionStore(
            redis,
            prefix=prefix,
            idle_timeout_s=settings.session_idle_timeout_s,
            absolute_timeout_s=settings.session_absolute_timeout_s,
            clock=clock,
        ),
        mfa_tokens=MfaTokenStore(redis, prefix=prefix),
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
