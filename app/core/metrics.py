"""Prometheus metrics (section 11), served at `/metrics`.

`/metrics` is not an API route: Nginx closes it on the public server block and
serves it only on 127.0.0.1 (deploy/nginx/admin-bff-internal.conf). It holds
counters only, no personal data.

Under Gunicorn every worker is a separate process, so the counters are kept in
files under `PROMETHEUS_MULTIPROC_DIR` (set by admin-bff.service, cleaned by
deploy/gunicorn.conf.py) and summed at scrape time. Without that variable
(development, tests) the process's own registry is served.

Labels are bounded: the route template (`/api/v1/admin/users/{user_id}`), never
the raw path.
"""

import os

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
)
from starlette.requests import Request
from starlette.responses import Response

from app.audit.sink import AuditEvent, AuditOutcome

METRICS_PATH = "/metrics"
UNMATCHED_ROUTE = "unmatched"

HTTP_REQUESTS = Counter(
    "admin_bff_http_requests_total", "HTTP requests", ["method", "route", "status"]
)
HTTP_DURATION = Histogram(
    "admin_bff_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
LOGIN_FAILURES = Counter("admin_bff_login_failures_total", "Failed sign-in attempts", ["step"])
LOGIN_LOCKOUTS = Counter("admin_bff_login_lockouts_total", "Login lockouts", ["rule"])
RATE_LIMITED = Counter("admin_bff_rate_limited_total", "Requests over a rate limit", ["limit"])
AUDIT_WRITE_FAILURES = Counter(
    "admin_bff_audit_write_failures_total", "Audit events the database did not store"
)


def observe_request(method: str, route: str, status: int, duration_s: float) -> None:
    HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
    HTTP_DURATION.labels(method=method, route=route).observe(duration_s)


class MetricsAuditListener:
    """Counts failed sign-ins and lockouts from the audit events."""

    async def write(self, event: AuditEvent) -> None:
        if event.action == "auth.login" and event.outcome is AuditOutcome.DENIED:
            step = event.details.get("step") or event.details.get("reason") or "unknown"
            LOGIN_FAILURES.labels(step=str(step)[:32]).inc()
        elif event.action == "auth.lockout":
            LOGIN_LOCKOUTS.labels(rule=str(event.details.get("rule", "unknown"))[:32]).inc()


async def metrics_endpoint(request: Request) -> Response:
    registry = REGISTRY
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
