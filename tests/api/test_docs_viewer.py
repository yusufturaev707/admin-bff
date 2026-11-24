"""The read-only docs viewer for the frontend developer (openapi/index.html,
deploy/nginx/admin-bff-docs.conf): every file it needs is in the repo."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIEWER = ROOT / "openapi"
SWAGGER = ROOT / "app" / "static" / "swagger-ui"
NGINX = (ROOT / "deploy" / "nginx" / "admin-bff-docs.conf").read_text(encoding="utf-8")


def test_the_page_uses_only_local_files() -> None:
    page = (VIEWER / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^"]+)"', page)
    assert refs
    for ref in refs:
        assert ref.startswith("/"), ref  # no CDN: the internal network blocks them
        if ref.startswith("/swagger-ui/"):
            assert (SWAGGER / ref.removeprefix("/swagger-ui/")).is_file(), ref
        else:
            assert (VIEWER / ref.lstrip("/")).is_file(), ref


def test_the_viewer_reads_the_snapshot_and_sends_nothing() -> None:
    script = (VIEWER / "viewer.js").read_text(encoding="utf-8")
    assert 'url: "/v1.json"' in script
    assert "supportedSubmitMethods: []" in script
    assert (VIEWER / "v1.json").is_file()


def test_nginx_serves_the_viewer_files_only() -> None:
    served = set(re.findall(r"location = /(\S+) \{\}", NGINX))
    assert served == {"index.html", "viewer.js", "v1.json"}
    assert all((VIEWER / name).is_file() for name in served)
    assert "include /etc/nginx/snippets/admin-allowlist.conf;" in NGINX
    assert "alias /srv/admin-bff/app/static/swagger-ui/;" in NGINX
