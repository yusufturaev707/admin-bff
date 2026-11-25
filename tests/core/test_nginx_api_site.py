"""The BFF's nginx sites (deploy/nginx/) behind the organisation's TLS proxy:
the proxy terminates HTTPS for *.uzbmb.uz and sends plain HTTP to port 8080
of this server, like the other *.uzbmb.uz sites there (seen in the server's
access log, 2026-11-24)."""

import re
from pathlib import Path

import pytest

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "nginx"
API, FRONTEND = "admin-api.conf", "admin-frontend.conf"
# admin-api.conf holds all of the BFF: the API, then the internal block on
# loopback. `_` only appears on a port no other site uses.
LISTENS = {API: ["8080", "127.0.0.1:18081"], FRONTEND: ["8080"]}
NAMES = {API: ["kpi.uzbmb.uz", "_"], FRONTEND: ["admin.uzbmb.uz"]}


def _conf(name: str) -> str:
    return (NGINX / name).read_text(encoding="utf-8")


def _directives(conf: str, name: str) -> list[str]:
    """Values of a directive, comments excluded."""
    return re.findall(rf"^\s*{name} ([^;]+);", conf, re.MULTILINE)


@pytest.mark.parametrize("name", [API, FRONTEND])
def test_the_site_answers_only_to_its_names_and_ports(name: str) -> None:
    conf = _conf(name)
    # Another project's IP-based or unknown-name traffic must never land here:
    # no default_server, and on the shared 8080 only the domain.
    assert _directives(conf, "listen") == LISTENS[name]
    assert _directives(conf, "server_name") == NAMES[name]


@pytest.mark.parametrize("name", [API, FRONTEND])
def test_no_tls_and_no_redirect_behind_the_proxy(name: str) -> None:
    # The proxy sends plain HTTP: a redirect to https here loops forever.
    conf = _conf(name)
    assert not _directives(conf, "ssl_certificate")
    assert "return 301" not in conf


@pytest.mark.parametrize("name", [API, FRONTEND])
def test_the_client_ip_is_trusted_only_from_the_proxy(name: str) -> None:
    conf = _conf(name)
    proxy = re.search(r"^\s+(\S+) 1;\s+# PROXY", _conf(API), re.MULTILINE)
    assert proxy is not None
    # Inside the server block only: at http level it would change every
    # other site on the server.
    assert re.findall(r"^    set_real_ip_from (\S+);", conf, re.MULTILINE) == [proxy.group(1)]
    assert not re.search(r"^set_real_ip_from", conf, re.MULTILINE)
    assert _directives(conf, "real_ip_header") == ["X-Forwarded-For"]
    assert _directives(conf, "real_ip_recursive") == ["on"]
    # Plain HTTP straight to <server_IP>:8080, past the proxy, is refused.
    assert re.search(r"if \(\$admin_bff_via_proxy = 0\) \{\s+return 403;", conf)


def test_the_api_tells_the_bff_the_real_client_and_scheme() -> None:
    conf = _conf(API)
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in conf
    assert "proxy_set_header X-Forwarded-Proto https;" in conf
    assert re.search(r"geo \$realip_remote_addr \$admin_bff_via_proxy \{", conf)


def test_the_api_keeps_internal_paths_closed_with_json_errors() -> None:
    conf = _conf(API)
    assert "location /internal/ { return 404; }" in conf
    assert "location = /metrics { return 404; }" in conf
    assert "include /etc/nginx/snippets/admin-allowlist.conf;" in conf
    for code, name in [("403", "forbidden"), ("404", "not_found"), ("502 503 504", "unavailable")]:
        assert f"error_page {code} = @{name};" in conf
    # The denial page itself must pass the allowlist, or nginx answers in HTML.
    assert re.search(r"location @forbidden \{\s+allow all;", conf)


def test_the_frontend_may_reach_the_api_domain() -> None:
    csp = re.search(r'Content-Security-Policy "([^"]+)"', _conf(FRONTEND))
    assert csp is not None
    assert f"connect-src 'self' https://{NAMES[API][0]};" in csp.group(1)


def test_the_internal_block_listens_on_loopback_only() -> None:
    conf = _conf(API)
    internal = conf.split("listen 127.0.0.1:18081;", 1)[1].split("\n}\n", 1)[0]
    assert "location = /internal/jwks.json {" in internal
    assert "location = /metrics {" in internal
    assert re.search(r"location / \{\s+return 404;", internal)
    assert not (NGINX / "admin-bff-internal.conf").exists()
    assert not (NGINX / "admin-bff-docs.conf").exists()
