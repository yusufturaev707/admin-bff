import secrets
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

import httpx
import pytest
from fastapi import APIRouter, FastAPI, Query
from pydantic import BaseModel

from app.core.errors import AppError, ErrorCode
from app.main import create_app
from app.settings import Settings
from tests.helpers import app_client

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str
    attempts: int


@router.get("/_test/conflict", operation_id="test_conflict_get")
async def conflict() -> None:
    raise AppError(ErrorCode.CONFLICT, details={"field": "username"})


@router.get("/_test/crash", operation_id="test_crash_get")
async def crash() -> None:
    raise RuntimeError("db password leaked 31201234560045")


@router.get("/_test/items", operation_id="test_items_list")
async def items(page: Annotated[int, Query(ge=1)]) -> dict[str, int]:
    return {"page": page}


@router.post("/_test/login", operation_id="test_login_create")
async def login(body: LoginBody) -> dict[str, str]:
    return {"username": body.username}


@pytest.fixture
async def error_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app: FastAPI = create_app(settings)
    app.include_router(router)
    async with app_client(app) as client:
        yield client


def _assert_error_shape(response: httpx.Response, status: int, code: str) -> dict[str, object]:
    assert response.status_code == status
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "message", "request_id", "details"}
    assert error["code"] == code
    assert isinstance(error["message"], str)
    assert error["message"]
    assert error["request_id"] == response.headers["X-Request-ID"]
    uuid.UUID(error["request_id"])
    return dict(error)


async def test_unknown_path_is_not_found(error_client: httpx.AsyncClient) -> None:
    response = await error_client.get("/api/v1/does-not-exist")
    _assert_error_shape(response, 404, "not_found")


async def test_wrong_method(error_client: httpx.AsyncClient) -> None:
    response = await error_client.delete("/health")
    _assert_error_shape(response, 405, "method_not_allowed")
    assert "GET" in response.headers["Allow"]


async def test_app_error(error_client: httpx.AsyncClient) -> None:
    response = await error_client.get("/_test/conflict")
    error = _assert_error_shape(response, 409, "conflict")
    assert error["details"] == {"field": "username"}


async def test_query_validation_error(error_client: httpx.AsyncClient) -> None:
    response = await error_client.get("/_test/items", params={"page": "0"})
    error = _assert_error_shape(response, 422, "validation_error")
    details = error["details"]
    assert isinstance(details, dict)
    [field] = details["fields"]
    assert field["loc"] == ["query", "page"]
    assert set(field) == {"loc", "type", "msg"}


async def test_validation_error_does_not_echo_input(error_client: httpx.AsyncClient) -> None:
    password = secrets.token_urlsafe(16)
    response = await error_client.post(
        "/_test/login", json={"username": "admin", "password": password, "attempts": password}
    )
    _assert_error_shape(response, 422, "validation_error")
    assert password not in response.text


async def test_malformed_json_is_validation_error(error_client: httpx.AsyncClient) -> None:
    response = await error_client.post(
        "/_test/login", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    _assert_error_shape(response, 422, "validation_error")


async def test_unhandled_exception_is_hidden(error_client: httpx.AsyncClient) -> None:
    response = await error_client.get("/_test/crash")
    error = _assert_error_shape(response, 500, "internal_error")
    assert error["message"] == "Ichki xatolik yuz berdi"
    assert "password" not in response.text
    assert "31201234560045" not in response.text
