#!/usr/bin/env bash
# Barcha CI tekshiruvlari. CI'da ham, lokal'da ham shu skript ishlatiladi:
#   bash scripts/ci.sh
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "uv sync (lock fayl o'zgarmagan bo'lishi shart)"
uv sync --frozen

step "ruff check"
uv run ruff check .

step "ruff format --check"
uv run ruff format --check .

step "mypy --strict"
uv run mypy --strict app/ tests/ scripts/

step "pytest + coverage (OpenAPI snapshot tekshiruvi ham shu yerda)"
uv run pytest --cov --cov-report=term --cov-report=json:coverage.json --cov-fail-under=80

step "coverage: auth/rbac/audit/service_auth kamida 90%, umumiy kamida 80%"
uv run python scripts/check_coverage.py coverage.json

step "bandit"
uv run bandit --quiet --recursive app

step "alembic: bittadan ortiq head bo'lmasin"
heads=$(uv run alembic heads | grep -c '(head)' || true)
if [ "$heads" -gt 1 ]; then
    echo "Alembic'da $heads ta head bor, migratsiyalarni birlashtiring (alembic merge)." >&2
    exit 1
fi

step "pip-audit (zaifliklar bazasiga tarmoq orqali murojaat qiladi)"
uv run pip-audit --strict --progress-spinner off

printf '\nCI: hammasi yashil.\n'
