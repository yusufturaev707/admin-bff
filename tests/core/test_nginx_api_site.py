"""The API site (deploy/nginx/admin-api.conf) works without a domain on
https://<server_IP>:8443 and with one on 443, where only the domain in
`server_name` and the certificate files change."""

import re
from pathlib import Path

API_SITE = (Path(__file__).resolve().parents[2] / "deploy" / "nginx" / "admin-api.conf").read_text(
    encoding="utf-8"
)


def test_the_api_listens_on_443_and_on_8443_for_the_ip() -> None:
    assert re.search(r"listen 443 ssl http2;\s+(#[^\n]*\n\s+)*listen 8443 ssl http2;", API_SITE)


def test_the_domain_is_the_only_name_on_the_shared_ports() -> None:
    # An IP in server_name on 80/443 would take over requests that reach
    # another project's site through the server's IP today.
    names = re.findall(r"^\s+server_name ([^;]+);", API_SITE, re.MULTILINE)
    assert names == ["admin-api.uzbmb.uz", "admin-api.uzbmb.uz"]
    assert not any(re.fullmatch(r"[\d.]+|_", n) for n in names)
    assert "default_server" not in API_SITE


def test_the_certificate_path_does_not_name_the_domain() -> None:
    assert "ssl_certificate     /etc/nginx/tls/admin-api/fullchain.pem;" in API_SITE
    assert "ssl_certificate_key /etc/nginx/tls/admin-api/privkey.pem;" in API_SITE
