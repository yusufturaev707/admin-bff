"""Coverage thresholds from section 12, checked on coverage.py's JSON report.

* `app/auth`, `app/rbac`, `app/audit`, `app/service_auth`: each at least 90%;
* the whole `app`: at least 80% (also enforced by pytest-cov's --cov-fail-under).

coverage.py has no per-package threshold, hence this script:
    uv run python scripts/check_coverage.py coverage.json
A package without code yet (a later phase) is reported and skipped.
"""

import json
import sys
from pathlib import Path
from typing import Any

CRITICAL_PACKAGES = ("app/auth", "app/rbac", "app/audit", "app/service_auth")
CRITICAL_MIN = 90.0
TOTAL_MIN = 80.0


def _percent(summary: dict[str, Any]) -> tuple[int, int]:
    """(covered, total) counting both lines and branches, like coverage.py."""
    covered = summary["covered_lines"] + summary.get("covered_branches", 0)
    total = summary["num_statements"] + summary.get("num_branches", 0)
    return covered, total


def _check(name: str, covered: int, total: int, minimum: float) -> bool:
    percent = 100.0 * covered / total
    ok = percent >= minimum
    status = "ok" if ok else "XATO"
    sys.stdout.write(f"{name}: {percent:.1f}% (kamida {minimum:.0f}%) {status}\n")
    return ok


def main(report_path: str) -> int:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    ok = True
    for package in CRITICAL_PACKAGES:
        covered = total = 0
        for name, data in report["files"].items():
            if Path(name).as_posix().startswith(package + "/"):
                file_covered, file_total = _percent(data["summary"])
                covered += file_covered
                total += file_total
        if total == 0:
            sys.stdout.write(f"{package}: kod hali yo'q, o'tkazib yuborildi\n")
            continue
        ok &= _check(package, covered, total, CRITICAL_MIN)
    ok &= _check("app", *_percent(report["totals"]), TOTAL_MIN)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
