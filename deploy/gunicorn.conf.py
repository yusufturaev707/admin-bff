"""Gunicorn config for production (used by deploy/admin-bff.service).

Gunicorn listens only on a unix socket; Nginx reaches it through the socket's
group (section 11). Nothing listens on a TCP port.
"""

import multiprocessing
import os
import shutil
from pathlib import Path
from typing import Any

from prometheus_client import multiprocess

bind = "unix:/run/admin-bff/bff.sock"
# Socket mode 0660 (umask 007): owner admin-bff, group admin-bff; Nginx's user
# (www-data) is a member of the admin-bff group.
umask = 0o007

worker_class = "uvicorn_worker.UvicornWorker"
# Memory budget (MemoryMax=1G in admin-bff.service). Measured: a worker takes
# about 90 MiB, plus ARGON2_MEMORY_COST_KIB (64 MiB) for every Argon2 check it
# runs at once (ARGON2_MAX_CONCURRENCY, 1 by default, app/auth/passwords.py).
# 4 workers peak at about 4 * (90 + 64) = 620 MiB. The workers are async and
# mostly wait on I/O, so 4 are plenty for the admin panel. Raising either
# number means raising MemoryMax too.
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count(), 4)))

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

# Gunicorn 25.1+ opens a control socket for `gunicornc` (worker count,
# shutdown) in $HOME/.gunicorn by default. The service has no home and a
# read-only file system, and nothing uses it: one interface less.
control_socket_disable = True

# The application writes its own JSON access log; Gunicorn's is disabled.
accesslog = None
errorlog = "-"
loglevel = "info"

# Prometheus multiprocess mode (app/core/metrics.py): every worker writes its
# counters to files in PROMETHEUS_MULTIPROC_DIR (admin-bff.service, on tmpfs).


def on_starting(server: Any) -> None:
    """Old workers' files would add stale counts: start empty."""
    directory = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if directory:
        shutil.rmtree(directory, ignore_errors=True)
        Path(directory).mkdir(mode=0o700, parents=True)


def child_exit(server: Any, worker: Any) -> None:
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        multiprocess.mark_process_dead(worker.pid)  # type: ignore[no-untyped-call]


limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
