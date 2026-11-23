"""API docs for the frontend developer: Swagger UI and the OpenAPI schema (section 10).

* `GET /api/v1/docs`: Swagger UI. Its assets are served from this app
  (`/api/v1/docs/static/`), because the internal network blocks CDNs.
* `GET /api/v1/openapi.json`: the schema.

Outside production both are open. In production they need a session with
`admin:api:docs`: sign in to the admin frontend, then open the docs URL on the
API domain in the same browser.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.rbac.dependencies import require_in_production

DOCS_URL = "/api/v1/docs"
OPENAPI_URL = "/api/v1/openapi.json"
STATIC_URL = f"{DOCS_URL}/static"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "swagger-ui"

# No inline script: the page works under a CSP without 'unsafe-inline'
# (deploy/nginx/admin-api.conf).
_PAGE = f"""<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UZBMB Admin BFF API</title>
<link rel="stylesheet" href="{STATIC_URL}/swagger-ui.css">
<link rel="icon" type="image/png" href="{STATIC_URL}/favicon-32x32.png">
</head>
<body>
<div id="swagger-ui"></div>
<script src="{STATIC_URL}/swagger-ui-bundle.js"></script>
<script src="{DOCS_URL}/init.js"></script>
</body>
</html>
"""

_INIT = f"""window.ui = SwaggerUIBundle({{
  url: "{OPENAPI_URL}",
  dom_id: "#swagger-ui",
  deepLinking: true,
  displayOperationId: true,
  docExpansion: "list",
  filter: true,
}});
"""

router = APIRouter(
    tags=["docs"],
    include_in_schema=False,
    dependencies=[Depends(require_in_production("admin:api:docs"))],
)


@router.get(DOCS_URL, operation_id="core_docs_get", response_class=HTMLResponse)
async def docs() -> HTMLResponse:
    return HTMLResponse(_PAGE, headers={"Cache-Control": "no-store"})


@router.get(f"{DOCS_URL}/init.js", operation_id="core_docsinit_get", response_class=Response)
async def docs_init() -> Response:
    return Response(_INIT, media_type="text/javascript", headers={"Cache-Control": "no-store"})


@router.get(OPENAPI_URL, operation_id="core_openapi_get")
async def openapi(request: Request) -> JSONResponse:
    return JSONResponse(request.app.openapi(), headers={"Cache-Control": "no-store"})


def static_files() -> StaticFiles:
    """Swagger UI itself (swagger-ui-dist, Apache-2.0; version in VERSION)."""
    return StaticFiles(directory=STATIC_DIR)
