"""Gunicorn config for production (used by deploy/admin-bff.service).

Gunicorn listens only on a unix socket; Nginx reaches it through the socket's
group (section 11). Nothing listens on a TCP port.
"""

import multiprocessing
import os

bind = "unix:/run/admin-bff/bff.sock"
# Socket mode 0660 (umask 007): owner admin-bff, group admin-bff; Nginx's user
# (www-data) is a member of the admin-bff group.
umask = 0o007

# TODO(owner): uvicorn.workers is deprecated upstream in favour of the
# `uvicorn-worker` package (same UvicornWorker class); switching needs approval
# for the new dependency.
worker_class = "uvicorn.workers.UvicornWorker"
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2, 8)))

# HUP (systemctl reload) restarts workers gracefully with the new code; this
# only works when the app is NOT preloaded in the arbiter.
preload_app = False
graceful_timeout = 30
timeout = 60
keepalive = 5

# The socket is reachable only by Nginx, which overwrites X-Forwarded-For with
# $remote_addr, so forwarded headers from the socket can be trusted.
forwarded_allow_ips = "*"

# Heartbeat files on tmpfs (the code directory is read-only under systemd).
worker_tmp_dir = "/run/admin-bff"

# The application writes its own JSON access log; Gunicorn's is disabled.
accesslog = None
errorlog = "-"
loglevel = "info"

limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
