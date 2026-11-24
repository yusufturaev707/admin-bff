"""The temporary test entry point (deploy/nginx/admin-bff-test.conf): the
same protections as the API site, and names that do not clash with it."""

import re
from pathlib import Path

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "nginx"
TEST_SITE = (NGINX / "admin-bff-test.conf").read_text(encoding="utf-8")
API_SITE = (NGINX / "admin-api.conf").read_text(encoding="utf-8")


def _names(conf: str) -> set[str]:
    upstreams = re.findall(r"^upstream (\S+) \{", conf, re.MULTILINE)
    zones = re.findall(r"zone=(\w+):", conf)
    caches = re.findall(r"ssl_session_cache shared:(\w+):", conf)
    return {*upstreams, *zones, *caches}


def test_both_sites_can_be_enabled_at_once() -> None:
    assert _names(TEST_SITE)
    assert not _names(TEST_SITE) & _names(API_SITE)


def test_internal_paths_stay_closed_and_sign_in_is_limited() -> None:
    assert "location /internal/ { return 404; }" in TEST_SITE
    assert "location = /metrics { return 404; }" in TEST_SITE
    assert "include /etc/nginx/snippets/admin-allowlist.conf;" in TEST_SITE
    assert re.search(r"location /api/v1/auth/ \{\s+limit_req zone=admin_bff_test_auth", TEST_SITE)


def test_host_keeps_the_port_for_the_origin_check() -> None:
    # Swagger's Origin is https://<IP>:8443; the BFF compares it with
    # X-Forwarded-Proto + Host (app/auth/csrf.py, allow_same_origin).
    assert "listen 8443 ssl;" in TEST_SITE
    assert "proxy_set_header Host $host:$server_port;" in TEST_SITE
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in TEST_SITE
