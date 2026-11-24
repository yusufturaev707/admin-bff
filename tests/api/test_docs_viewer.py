"""The read-only docs viewer for the frontend developer (openapi/index.html,
deploy/nginx/admin-api.conf, part 3): every file it needs is in the repo, and it
answers on the API's own paths, so only the host changes once the domain is
connected."""

import re
from pathlib import Path

from app.api.docs import DOCS_URL, OPENAPI_URL, STATIC_URL

ROOT = Path(__file__).resolve().parents[2]
VIEWER = ROOT / "openapi"
SWAGGER = ROOT / "app" / "static" / "swagger-ui"
NGINX = (ROOT / "deploy" / "nginx" / "admin-api.conf").read_text(encoding="utf-8")
STATIC = f"{STATIC_URL}/"
# URL -> file in openapi/
FILES = {
    DOCS_URL: "index.html",
    f"{DOCS_URL}/viewer.js": "viewer.js",
    OPENAPI_URL: "v1.json",
}


def test_the_page_uses_only_local_files() -> None:
    page = (VIEWER / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^"]+)"', page)
    assert refs
    for ref in refs:
        if ref.startswith(STATIC):  # no CDN: the internal network blocks them
            assert (SWAGGER / ref.removeprefix(STATIC)).is_file(), ref
        else:
            assert ref in FILES, ref


def test_the_viewer_reads_the_schema_and_sends_nothing() -> None:
    script = (VIEWER / "viewer.js").read_text(encoding="utf-8")
    assert f'url: "{OPENAPI_URL}"' in script
    assert "supportedSubmitMethods: []" in script


def test_nginx_answers_on_the_api_paths() -> None:
    served = dict(
        re.findall(r"location = (\S+) \{\s+(?:default_type \S+;\s+)?try_files /(\S+) =404;", NGINX)
    )
    assert served == FILES
    assert all((VIEWER / name).is_file() for name in served.values())
    assert re.search(
        rf"location {re.escape(STATIC)} \{{\s+alias /srv/admin-bff/app/static/swagger-ui/;", NGINX
    )
    assert "include /etc/nginx/snippets/admin-allowlist.conf;" in NGINX
