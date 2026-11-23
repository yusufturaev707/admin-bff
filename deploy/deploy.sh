#!/usr/bin/env bash
# Admin BFF'ni yangilash: git pull -> uv sync -> alembic upgrade -> reload.
# root sifatida ishga tushiriladi:  sudo /opt/admin-bff/deploy/deploy.sh
#
# Kod root'ga tegishli va servis uchun faqat o'qish uchun ochiq
# (ProtectSystem=strict): servis o'z kodini o'zgartira olmaydi.
set -euo pipefail

APP_DIR=/opt/admin-bff
CREDENTIALS=/etc/admin-bff/credentials
UV=${UV:-/usr/local/bin/uv}

cd "$APP_DIR"

echo "==> git pull"
git pull --ff-only

echo "==> uv sync"
# --compile-bytecode: kod papkasi read-only, .pyc oldindan yaratiladi.
# Python: Debian 13'ning o'z python3.13 paketi (.python-version = 3.13).
# Ichki tarmoqda tashqi yuklab olish yopiq, shuning uchun uv Python'ni
# hech qachon internetdan yuklamaydi: tizimda topilmasa, xato beradi.
UV_PYTHON_DOWNLOADS=never "$UV" sync --frozen --no-dev --compile-bytecode

echo "==> alembic upgrade head"
# Migratsiya servis bilan bir xil sozlamalar va credential'lardan foydalanadi.
# TODO(owner): 3-bosqichda migratsiyalar alohida DB egasi (owner) user'i bilan
# bajariladi, chunki ilova user'i audit jadvalida faqat INSERT qila oladi.
set -a
# shellcheck disable=SC1091
. /etc/admin-bff/admin-bff.env
set +a
APP_ENV=production CREDENTIALS_DIRECTORY="$CREDENTIALS" \
    "$APP_DIR/.venv/bin/alembic" upgrade head

echo "==> systemctl reload admin-bff"
systemctl reload admin-bff

echo "==> health"
curl --silent --show-error --fail --unix-socket /run/admin-bff/bff.sock http://localhost/ready
echo
echo "Tayyor."
