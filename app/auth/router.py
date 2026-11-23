"""/api/v1/auth endpoints (section 6)."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse

from app.auth.dependencies import (
    AuthenticatedSession,
    AuthServiceDep,
    CurrentSession,
    RequestMetaDep,
    clear_session_cookie,
    set_session_cookie,
)
from app.auth.schemas import (
    CodeRequest,
    LoginRequest,
    LoginResponse,
    MfaRequest,
    PasswordChangeRequest,
    SessionInfo,
    SessionList,
    SessionListItem,
    SessionStartedResponse,
    StepUpResponse,
    TotpConfirmResponse,
    TotpEnrollResponse,
)
from app.auth.second_factor import RecoveryFactor, SecondFactor, TotpFactor
from app.auth.service import MfaRequired, OneIdLoginError
from app.auth.sessions import SessionData
from app.core.errors import AppError, ErrorCode, ErrorResponse
from app.settings import Settings

ONEID_STATE_COOKIE = "__Host-admin_oneid_state"
ONEID_STATE_MAX_AGE_S = 5 * 60

# Frontend pages the OneID callback redirects to (docs/frontend.md).
FRONTEND_MFA_PATH = "/login/mfa"
FRONTEND_SETUP_PATH = "/login/setup"
FRONTEND_ERROR_PATH = "/login?error=oneid_failed"


async def _no_store(response: Response) -> None:
    # Auth responses carry tokens: never cached by the browser or a proxy.
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/api/v1/auth", tags=["auth"], dependencies=[Depends(_no_store)])


def _errors(*statuses: int) -> dict[int | str, dict[str, Any]]:
    return {status: {"model": ErrorResponse} for status in statuses}


def _started(session: SessionData) -> SessionStartedResponse:
    return SessionStartedResponse(
        csrf_token=session.csrf_token,
        setup_required=session.setup_required,
        pending=list(session.pending),
    )


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@router.post(
    "/login",
    operation_id="auth_login_submit",
    summary="Login va parol",
    responses=_errors(401, 403, 422, 429),
)
async def login(
    body: LoginRequest, response: Response, service: AuthServiceDep, meta: RequestMetaDep
) -> LoginResponse:
    result = await service.login_password(body.username, body.password, meta)
    if isinstance(result, MfaRequired):
        return LoginResponse(mfa_required=True, mfa_token=result.mfa_token)
    set_session_cookie(response, result.session_id)
    return LoginResponse(
        mfa_required=False,
        setup_required=result.session.setup_required,
        pending=list(result.session.pending),
        csrf_token=result.session.csrf_token,
    )


@router.post(
    "/mfa",
    operation_id="auth_mfa_submit",
    summary="TOTP yoki recovery code bilan kirishni yakunlash",
    responses=_errors(401, 403, 422, 429),
)
async def mfa(
    body: MfaRequest, response: Response, service: AuthServiceDep, meta: RequestMetaDep
) -> SessionStartedResponse:
    factor: SecondFactor = (
        TotpFactor(body.code) if body.code is not None else RecoveryFactor(body.recovery_code or "")
    )
    started = await service.complete_mfa(body.mfa_token, factor, meta)
    set_session_cookie(response, started.session_id)
    return _started(started.session)


@router.post(
    "/logout",
    status_code=204,
    operation_id="auth_logout_submit",
    summary="Joriy sessiyani tugatish",
    responses=_errors(401, 403),
)
async def logout(
    response: Response, session: CurrentSession, service: AuthServiceDep, meta: RequestMetaDep
) -> None:
    await service.logout(session, meta)
    clear_session_cookie(response)


@router.get(
    "/session",
    operation_id="auth_session_get",
    summary="Joriy sessiya va CSRF token",
    responses=_errors(401),
)
async def get_session(session: CurrentSession, service: AuthServiceDep) -> SessionInfo:
    return SessionInfo(
        id=session.key,
        user_id=str(session.user_id),
        username=session.username,
        auth_method=session.auth_method,
        created_at=session.created_at,
        last_seen=session.last_seen,
        expires_at=service.sessions.expires_at(session),
        mfa_at=session.mfa_at,
        setup_required=session.setup_required,
        pending=list(session.pending),
        csrf_token=session.csrf_token,
    )


@router.get(
    "/sessions",
    operation_id="auth_sessions_list",
    summary="Adminning faol sessiyalari",
    responses=_errors(401, 403),
)
async def list_sessions(session: AuthenticatedSession, service: AuthServiceDep) -> SessionList:
    return SessionList(
        items=[
            SessionListItem(
                id=s.key,
                auth_method=s.auth_method,
                created_at=s.created_at,
                last_seen=s.last_seen,
                ip=s.ip,
                user_agent=s.user_agent,
                current=s.key == session.key,
            )
            for s in await service.list_sessions(session)
        ]
    )


@router.delete(
    "/sessions/{session_id}",
    status_code=204,
    operation_id="auth_sessions_delete",
    summary="O'z sessiyasini tugatish",
    responses=_errors(401, 403, 404),
)
async def delete_session(
    session_id: str,
    response: Response,
    session: AuthenticatedSession,
    service: AuthServiceDep,
    meta: RequestMetaDep,
) -> None:
    if await service.revoke_session(session, session_id, meta):
        clear_session_cookie(response)


@router.post(
    "/password",
    status_code=204,
    operation_id="auth_password_change",
    summary="Parolni almashtirish (barcha sessiyalar tugaydi)",
    responses=_errors(401, 403, 409, 422, 429),
)
async def change_password(
    body: PasswordChangeRequest,
    response: Response,
    session: CurrentSession,
    service: AuthServiceDep,
    meta: RequestMetaDep,
) -> None:
    await service.change_password(session, body.old_password, body.new_password, body.code, meta)
    clear_session_cookie(response)


@router.post(
    "/totp/enroll",
    operation_id="auth_totp_enroll",
    summary="TOTP ulashni boshlash",
    responses=_errors(401, 403, 409),
)
async def totp_enroll(
    session: CurrentSession, service: AuthServiceDep, meta: RequestMetaDep
) -> TotpEnrollResponse:
    enrollment = await service.enroll_totp(session, meta)
    return TotpEnrollResponse(secret=enrollment.secret, otpauth_uri=enrollment.otpauth_uri)


@router.post(
    "/totp/confirm",
    operation_id="auth_totp_confirm",
    summary="TOTP'ni kod bilan tasdiqlash",
    responses=_errors(401, 403, 409, 422),
)
async def totp_confirm(
    body: CodeRequest,
    response: Response,
    session: CurrentSession,
    service: AuthServiceDep,
    meta: RequestMetaDep,
) -> TotpConfirmResponse:
    confirmed = await service.confirm_totp(session, body.code, meta)
    set_session_cookie(response, confirmed.started.session_id)
    new = confirmed.started.session
    return TotpConfirmResponse(
        csrf_token=new.csrf_token,
        setup_required=new.setup_required,
        pending=list(new.pending),
        recovery_codes=confirmed.recovery_codes,
    )


@router.post(
    "/step-up",
    operation_id="auth_step_up_submit",
    summary="Xavfli amaldan oldin TOTP'ni qayta kiritish",
    responses=_errors(401, 403, 422, 429),
)
async def step_up(
    body: CodeRequest, session: AuthenticatedSession, service: AuthServiceDep, meta: RequestMetaDep
) -> StepUpResponse:
    updated = await service.step_up(session, body.code, meta)
    if updated.mfa_at is None:  # pragma: no cover - set by step_up
        raise AppError(ErrorCode.INTERNAL_ERROR)
    return StepUpResponse(mfa_at=updated.mfa_at)


@router.get(
    "/oneid/start",
    status_code=302,
    response_class=RedirectResponse,
    operation_id="auth_oneid_start",
    summary="OneID orqali kirish (brauzer shu manzilga o'tadi)",
    responses={302: {"description": "OneID sahifasiga yo'naltirish"}, **_errors(404)},
)
async def oneid_start(service: AuthServiceDep) -> RedirectResponse:
    if not service.oneid_enabled:
        raise AppError(ErrorCode.NOT_FOUND)
    url, state = await service.oneid_start()
    response = RedirectResponse(url, status_code=302)
    response.headers["Cache-Control"] = "no-store"
    # SameSite=Lax: the callback is a top-level navigation coming from OneID.
    response.set_cookie(
        ONEID_STATE_COOKIE,
        state,
        max_age=ONEID_STATE_MAX_AGE_S,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get(
    "/oneid/callback",
    status_code=302,
    response_class=RedirectResponse,
    operation_id="auth_oneid_callback",
    summary="OneID qaytish manzili (frontendga yo'naltiradi)",
    responses={302: {"description": "Frontend sahifasiga yo'naltirish"}, **_errors(404)},
)
async def oneid_callback(
    request: Request,
    service: AuthServiceDep,
    meta: RequestMetaDep,
    code: Annotated[str | None, Query(max_length=2048)] = None,
    state: Annotated[str | None, Query(max_length=256)] = None,
) -> RedirectResponse:
    if not service.oneid_enabled:
        raise AppError(ErrorCode.NOT_FOUND)
    frontend = _settings(request).frontend_origin or ""
    try:
        result = await service.oneid_callback(
            code, state, request.cookies.get(ONEID_STATE_COOKIE), meta
        )
    except OneIdLoginError:
        response = RedirectResponse(frontend + FRONTEND_ERROR_PATH, status_code=302)
    else:
        if isinstance(result, MfaRequired):
            # In the fragment: never sent to a server, not in Referer or access logs.
            # The frontend reads it and removes it from the address bar at once.
            response = RedirectResponse(
                f"{frontend}{FRONTEND_MFA_PATH}#mfa_token={result.mfa_token}", status_code=302
            )
        else:
            response = RedirectResponse(frontend + FRONTEND_SETUP_PATH, status_code=302)
            set_session_cookie(response, result.session_id)
    response.headers["Cache-Control"] = "no-store"
    response.delete_cookie(ONEID_STATE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response
