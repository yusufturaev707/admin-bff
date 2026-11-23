"""Unified error format (section 10).

Every error leaves the BFF as::

    {"error": {"code": "forbidden", "message": "...", "request_id": "...", "details": {}}}

`code` is a stable English identifier for the frontend; `message` is Uzbek text
for the user. Internal exception texts and upstream system messages are never
passed through.
"""

from collections.abc import Mapping, Sequence
from enum import StrEnum
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.core.request_id import REQUEST_ID_HEADER, get_request_id

logger = get_logger(__name__)


class ErrorCode(StrEnum):
    NOT_AUTHENTICATED = "not_authenticated"
    SESSION_EXPIRED = "session_expired"
    FORBIDDEN = "forbidden"
    STEP_UP_REQUIRED = "step_up_required"
    CSRF_FAILED = "csrf_failed"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    VALIDATION_ERROR = "validation_error"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    SYSTEM_UNAVAILABLE = "system_unavailable"
    UPSTREAM_ERROR = "upstream_error"
    INTERNAL_ERROR = "internal_error"


# code -> (default HTTP status, default Uzbek message)
_DEFAULTS: dict[ErrorCode, tuple[int, str]] = {
    ErrorCode.NOT_AUTHENTICATED: (401, "Tizimga kirish talab qilinadi"),
    ErrorCode.SESSION_EXPIRED: (401, "Sessiya muddati tugagan, qaytadan kiring"),
    ErrorCode.FORBIDDEN: (403, "Bu amal uchun ruxsat yo'q"),
    ErrorCode.STEP_UP_REQUIRED: (401, "Bu amal uchun TOTP kodni qayta kiriting"),
    ErrorCode.CSRF_FAILED: (403, "So'rov xavfsizlik tekshiruvidan o'tmadi"),
    ErrorCode.NOT_FOUND: (404, "Ma'lumot topilmadi"),
    ErrorCode.METHOD_NOT_ALLOWED: (405, "Bu metod qo'llab-quvvatlanmaydi"),
    ErrorCode.VALIDATION_ERROR: (422, "Kiritilgan ma'lumotlar noto'g'ri"),
    ErrorCode.CONFLICT: (409, "So'rov joriy holatga zid, amalni bajarib bo'lmadi"),
    ErrorCode.RATE_LIMITED: (429, "So'rovlar soni chegaradan oshdi, birozdan keyin urinib ko'ring"),
    ErrorCode.SYSTEM_UNAVAILABLE: (503, "Tizim vaqtincha ishlamayapti"),
    ErrorCode.UPSTREAM_ERROR: (502, "Tizimdan noto'g'ri javob keldi"),
    ErrorCode.INTERNAL_ERROR: (500, "Ichki xatolik yuz berdi"),
}

_STATUS_TO_CODE: dict[int, ErrorCode] = {
    400: ErrorCode.VALIDATION_ERROR,
    401: ErrorCode.NOT_AUTHENTICATED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    405: ErrorCode.METHOD_NOT_ALLOWED,
    409: ErrorCode.CONFLICT,
    422: ErrorCode.VALIDATION_ERROR,
    429: ErrorCode.RATE_LIMITED,
    502: ErrorCode.UPSTREAM_ERROR,
    503: ErrorCode.SYSTEM_UNAVAILABLE,
    504: ErrorCode.SYSTEM_UNAVAILABLE,
}


class ErrorBody(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "code": "forbidden",
                "message": "Bu amal uchun ruxsat yo'q",
                "request_id": "0b9c5e1e-3f7a-4d43-9a43-6f1a2b9d8c11",
                "details": {},
            }
        }
    )

    code: ErrorCode
    message: str
    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody


class AppError(Exception):
    """Raise anywhere in request handling to return a unified error."""

    def __init__(
        self,
        code: ErrorCode,
        message: str | None = None,
        *,
        status_code: int | None = None,
        details: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        default_status, default_message = _DEFAULTS[code]
        self.code = code
        self.message = message or default_message
        self.status_code = status_code or default_status
        self.details = dict(details or {})
        self.headers = dict(headers or {})
        super().__init__(f"{code}: {self.message}")


def field_error(loc: Sequence[str], error_type: str, message: str) -> AppError:
    """A 422 for one form field, in the same shape as request validation errors."""
    return AppError(
        ErrorCode.VALIDATION_ERROR,
        message,
        details={"fields": [{"loc": list(loc), "type": error_type, "msg": message}]},
    )


def error_response(
    request: Request,
    code: ErrorCode,
    *,
    status_code: int | None = None,
    message: str | None = None,
    details: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    default_status, default_message = _DEFAULTS[code]
    request_id = get_request_id(request)
    body = ErrorResponse(
        error=ErrorBody(
            code=code,
            message=message or default_message,
            request_id=request_id,
            details=dict(details or {}),
        )
    )
    response_headers = dict(headers or {})
    if request_id is not None:
        response_headers[REQUEST_ID_HEADER] = request_id
    return JSONResponse(
        status_code=status_code or default_status,
        content=body.model_dump(mode="json"),
        headers=response_headers,
    )


def _code_for_status(status_code: int) -> ErrorCode:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    return ErrorCode.INTERNAL_ERROR if status_code >= 500 else ErrorCode.VALIDATION_ERROR


async def _app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):  # pragma: no cover - guaranteed by registration
        return await _unhandled_error_handler(request, exc)
    return error_response(
        request,
        exc.code,
        status_code=exc.status_code,
        message=exc.message,
        details=exc.details,
        headers=exc.headers,
    )


async def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover
        return await _unhandled_error_handler(request, exc)
    # `exc.detail` is deliberately ignored: it may carry internal text.
    status_code = exc.status_code if exc.status_code in HTTPStatus else 500
    return error_response(
        request,
        _code_for_status(status_code),
        status_code=status_code,
        headers=exc.headers,
    )


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        return await _unhandled_error_handler(request, exc)
    # Only location, type and pydantic's message are returned. The rejected
    # input itself is dropped: it may be a password or personal data.
    fields = [
        {"loc": [str(part) for part in err.get("loc", ())], "type": err.get("type", "")}
        | {"msg": str(err.get("msg", ""))}
        for err in exc.errors()
    ]
    return error_response(request, ErrorCode.VALIDATION_ERROR, details={"fields": fields})


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_exception", exc_info=exc, path=request.url.path)
    return error_response(request, ErrorCode.INTERNAL_ERROR)


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
