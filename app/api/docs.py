"""API docs for the frontend developer: Swagger UI and the OpenAPI schema (section 10).

* `GET /api/v1/docs`: Swagger UI with a sign-in bar (login, password,
  sign-out). Its assets are served from this app
  (`/api/v1/docs/static/`), because the internal network blocks CDNs.
* `GET /api/v1/openapi.json`: the schema. Every operation states its access:
  `security` (session cookie, plus the CSRF header for unsafe methods),
  and `x-permissions`.

"Try it out" works like the frontend: the session cookie is set by the sign-in
response, and the page adds the CSRF token (kept in memory only) to every
POST, PUT, PATCH and DELETE.

Outside production everything is open, and the Origin check also accepts the
API's own origin, so requests from this page pass. In production the docs need
a session with `admin:api:docs` (sign in to the admin frontend first) and are
read-only: unsafe requests from here fail the Origin check.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.dependencies.models import Dependant
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.staticfiles import StaticFiles

from app.auth.csrf import UNSAFE_METHODS
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE
from app.core.guards import guard_permissions
from app.rbac.dependencies import require_in_production
from app.rbac.route_check import PUBLIC_PATHS

DOCS_URL = "/api/v1/docs"
OPENAPI_URL = "/api/v1/openapi.json"
STATIC_URL = f"{DOCS_URL}/static"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "swagger-ui"

# No inline script or style: the page works under a strict CSP
# (deploy/nginx/admin-api.conf).
_PAGE = f"""<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UZBMB Admin BFF API</title>
<link rel="stylesheet" href="{STATIC_URL}/swagger-ui.css">
<link rel="stylesheet" href="{DOCS_URL}/docs.css">
<link rel="icon" type="image/png" href="{STATIC_URL}/favicon-32x32.png">
</head>
<body>
<form id="bff-bar" autocomplete="on">
  <strong>UZBMB Admin BFF</strong>
  <span id="bff-status">...</span>
  <span id="bff-fields">
    <input id="bff-username" name="username" autocomplete="username" placeholder="login">
    <input id="bff-password" name="password" type="password" autocomplete="current-password"
           placeholder="parol">
    <button type="submit" id="bff-login">Kirish</button>
  </span>
  <button type="button" id="bff-logout" hidden>Chiqish</button>
  <span id="bff-note"></span>
</form>
<div id="swagger-ui"></div>
<script src="{STATIC_URL}/swagger-ui-bundle.js"></script>
<script src="{DOCS_URL}/init.js"></script>
</body>
</html>
"""

_CSS = """#bff-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  padding: 10px 20px; background: #1b1b1b; color: #fff; font: 14px sans-serif; }
#bff-bar input { padding: 4px 6px; width: 150px; }
#bff-bar button { padding: 4px 10px; cursor: pointer; }
#bff-status.ok { color: #7ee787; }
#bff-status.err { color: #ff9b9b; }
#bff-note { color: #bbb; }
"""

_INIT = """(() => {
  "use strict";
  const SIGN_IN = __SIGN_IN__;
  const API = "/api/v1";
  const UNSAFE = ["POST", "PUT", "PATCH", "DELETE"];
  const $ = (id) => document.getElementById(id);
  let csrf = null;  // memory only, like the frontend (docs/frontend.md)

  const remember = (body) => {
    if (body && typeof body === "object" && typeof body.csrf_token === "string") {
      csrf = body.csrf_token;
    }
  };
  const show = (text, ok) => {
    $("bff-status").textContent = text;
    $("bff-status").className = ok ? "ok" : "err";
  };
  const problem = (res) => (res.data && res.data.error)
    ? res.data.error.code + ": " + res.data.error.message : "HTTP " + res.status;

  async function call(method, path, body) {
    const headers = {"Content-Type": "application/json"};
    if (csrf && UNSAFE.includes(method)) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(API + path, {
      method, headers, credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = null;
    try { data = await response.json(); } catch (e) { data = null; }
    remember(data);
    return {status: response.status, data};
  }

  async function refresh() {
    const res = await call("GET", "/auth/session");
    if (res.status === 200) {
      const pending = res.data.pending || [];
      show("Kirilgan: " + res.data.username + (pending.length
        ? " (avval yakunlang: " + pending.join(", ") + ")" : ""), true);
      $("bff-logout").hidden = !SIGN_IN;
    } else {
      csrf = null;
      show("Kirilmagan", false);
      $("bff-logout").hidden = true;
    }
  }

  async function signIn(event) {
    event.preventDefault();
    const res = await call("POST", "/auth/login",
      {username: $("bff-username").value, password: $("bff-password").value});
    $("bff-password").value = "";
    if (res.status !== 200) return show(problem(res), false);
    await refresh();
  }

  async function signOut() {
    await call("POST", "/auth/logout");
    await refresh();
  }

  if (SIGN_IN) {
    $("bff-bar").addEventListener("submit", signIn);
    $("bff-logout").addEventListener("click", signOut);
    $("bff-note").textContent = "CSRF token o'zi qo'shiladi";
  } else {
    $("bff-fields").hidden = true;
    $("bff-note").textContent = "Production: adminka orqali kiring, bu yerda faqat o'qish";
  }

  window.ui = SwaggerUIBundle({
    url: API + "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    displayOperationId: true,
    displayRequestDuration: true,
    docExpansion: "none",
    defaultModelsExpandDepth: 0,
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    tryItOutEnabled: SIGN_IN,
    queryConfigEnabled: false,
    withCredentials: true,
    requestInterceptor: (request) => {
      if (csrf && UNSAFE.includes(String(request.method || "GET").toUpperCase())) {
        request.headers["X-CSRF-Token"] = csrf;
      }
      return request;
    },
    responseInterceptor: (response) => {
      try {
        remember(typeof response.body === "object" ? response.body : JSON.parse(response.text));
      } catch (e) { /* not JSON */ }
      if (String(response.url || "").includes("/api/v1/auth/")) refresh();
      return response;
    },
  });
  refresh();
})();
"""

router = APIRouter(
    tags=["docs"],
    include_in_schema=False,
    dependencies=[Depends(require_in_production("admin:api:docs"))],
)
_NO_STORE = {"Cache-Control": "no-store"}


@router.get(DOCS_URL, operation_id="core_docs_get", response_class=HTMLResponse)
async def docs() -> HTMLResponse:
    return HTMLResponse(_PAGE, headers=_NO_STORE)


@router.get(f"{DOCS_URL}/init.js", operation_id="core_docsinit_get", response_class=Response)
async def docs_init(request: Request) -> Response:
    settings = request.app.state.settings
    script = _INIT.replace("__SIGN_IN__", "false" if settings.is_production else "true")
    return Response(script, media_type="text/javascript", headers=_NO_STORE)


@router.get(f"{DOCS_URL}/docs.css", operation_id="core_docscss_get", response_class=Response)
async def docs_css() -> Response:
    return Response(_CSS, media_type="text/css", headers=_NO_STORE)


@router.get(OPENAPI_URL, operation_id="core_openapi_get")
async def openapi(request: Request) -> JSONResponse:
    return JSONResponse(request.app.openapi(), headers=_NO_STORE)


def static_files() -> StaticFiles:
    """Swagger UI itself (swagger-ui-dist, Apache-2.0; version in VERSION)."""
    return StaticFiles(directory=STATIC_DIR)


# --- access in the schema --------------------------------------------------------

SECURITY_SCHEMES: dict[str, Any] = {
    "session": {
        "type": "apiKey",
        "in": "cookie",
        "name": SESSION_COOKIE,
        "description": "HttpOnly sessiya cookie'si: `POST /api/v1/auth/login` o'rnatadi.",
    },
    "csrf": {
        "type": "apiKey",
        "in": "header",
        "name": CSRF_HEADER,
        "description": "Login javobidagi yoki `GET /api/v1/auth/session`dagi `csrf_token`.",
    },
}


def _calls(dependant: Dependant) -> Iterator[Callable[..., Any] | None]:
    for sub in dependant.dependencies:
        yield sub.call
        yield from _calls(sub)


def _describe_access(app: FastAPI, schema: dict[str, Any]) -> None:
    schema.setdefault("components", {})["securitySchemes"] = SECURITY_SCHEMES
    paths: dict[str, dict[str, Any]] = schema.get("paths", {})
    for context in iter_route_contexts(app.routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        path = context.path or ""
        operations = paths.get(path)
        if operations is None:  # not in the schema
            continue
        calls = list(_calls(context.dependant))
        permissions = sorted({p for c in calls for p in guard_permissions(c) or ()})
        for method in context.methods or ():
            operation = operations.get(method.lower())
            if operation is None:
                continue
            notes: list[str] = []
            if path in PUBLIC_PATHS:
                operation["security"] = []
            else:
                operation["security"] = (
                    [{"session": [], "csrf": []}] if method in UNSAFE_METHODS else [{"session": []}]
                )
            if permissions:
                operation["x-permissions"] = permissions
                notes.append("**Permission:** " + ", ".join(f"`{p}`" for p in permissions))
            if notes:
                text = operation.get("description", "")
                operation["description"] = "\n\n".join([*([text] if text else []), *notes])


def install_openapi(app: FastAPI) -> None:
    """Wraps FastAPI's schema generation (which caches the schema in
    `app.openapi_schema`) to add the access of every operation."""
    generate = app.openapi

    def openapi_with_access() -> dict[str, Any]:
        schema = app.openapi_schema
        if schema is None:
            schema = generate()  # also stores it in app.openapi_schema
            _describe_access(app, schema)
        return schema

    app.openapi = openapi_with_access  # type: ignore[method-assign]
