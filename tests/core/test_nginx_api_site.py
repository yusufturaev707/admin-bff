"""The API and frontend sites (deploy/nginx/) answer only to their domain:
installing them means writing the domain into `server_name` and putting the
certificate into a path that does not name the domain."""

import re
from pathlib import Path

import pytest

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "nginx"
SITES = {
    "admin-api.conf": ("kpi.uzbmb.uz", "/etc/nginx/tls/admin-api"),
    "admin-frontend.conf": ("admin.uzbmb.uz", "/etc/nginx/tls/admin-frontend"),
}
# admin-api.conf holds all of the BFF: the API, then the internal block on
# loopback and the read-only docs on their own port. `_` only appears on ports
# no other site uses.
LISTENS = {
    "admin-api.conf": ["80", "443 ssl http2", "127.0.0.1:18081", "8090"],
    "admin-frontend.conf": ["80", "443 ssl http2"],
}
EXTRA_NAMES = {"admin-api.conf": ["_", "_"], "admin-frontend.conf": []}


def _conf(name: str) -> str:
    return (NGINX / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", SITES)
def test_the_site_answers_only_to_its_domain(name: str) -> None:
    conf = _conf(name)
    domain, _ = SITES[name]
    # Directives only, not the comments that mention them.
    names = re.findall(r"^\s+server_name ([^;]+);", conf, re.MULTILINE)
    assert names == [domain, domain, *EXTRA_NAMES[name]]
    listens = re.findall(r"^\s+listen ([^;]+);", conf, re.MULTILINE)
    # Another project's IP-based or unknown-name traffic must never land here:
    # no default_server, and on 80/443 only the domain.
    assert listens == LISTENS[name]


@pytest.mark.parametrize("name", SITES)
def test_the_certificate_path_does_not_name_the_domain(name: str) -> None:
    conf = _conf(name)
    _, tls = SITES[name]
    assert f"ssl_certificate     {tls}/fullchain.pem;" in conf
    assert f"ssl_certificate_key {tls}/privkey.pem;" in conf


@pytest.mark.parametrize("name", SITES)
def test_port_80_only_redirects_and_hides_the_version(name: str) -> None:
    plain = _conf(name).split("listen 80;", 1)[1].split("}", 1)[0]
    assert "return 301 https://$host$request_uri;" in plain
    assert "server_tokens off;" in plain
    # `return` runs before allow/deny: an allowlist here would only look active.
    assert "admin-allowlist" not in plain


def test_the_api_keeps_internal_paths_closed_with_json_errors() -> None:
    conf = _conf("admin-api.conf")
    assert "location /internal/ { return 404; }" in conf
    assert "location = /metrics { return 404; }" in conf
    assert "include /etc/nginx/snippets/admin-allowlist.conf;" in conf
    for code, name in [("403", "forbidden"), ("404", "not_found"), ("502 503 504", "unavailable")]:
        assert f"error_page {code} = @{name};" in conf
    # The denial page itself must pass the allowlist, or nginx answers in HTML.
    assert re.search(r"location @forbidden \{\s+allow all;", conf)


def test_the_frontend_may_reach_the_api_domain() -> None:
    api_domain = SITES["admin-api.conf"][0]
    csp = re.search(r'Content-Security-Policy "([^"]+)"', _conf("admin-frontend.conf"))
    assert csp is not None
    assert f"connect-src 'self' https://{api_domain};" in csp.group(1)


def test_the_internal_block_listens_on_loopback_only() -> None:
    conf = _conf("admin-api.conf")
    internal = conf.split("listen 127.0.0.1:18081;", 1)[1].split("\n}\n", 1)[0]
    assert "location = /internal/jwks.json {" in internal
    assert "location = /metrics {" in internal
    assert re.search(r"location / \{\s+return 404;", internal)
    assert not (NGINX / "admin-bff-internal.conf").exists()
    assert not (NGINX / "admin-bff-docs.conf").exists()
