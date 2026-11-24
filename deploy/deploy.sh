#!/usr/bin/env bash
# Admin BFF'ni yangilash: git pull -> uv sync -> alembic upgrade -> reload.
# root sifatida ishga tushiriladi:  sudo /srv/admin-bff/deploy/deploy.sh
#
# Kod root'ga tegishli va servis uchun faqat o'qish uchun ochiq
# (ProtectSystem=strict): servis o'z kodini o'zgartira olmaydi.
set -euo pipefail

APP_DIR=/srv/admin-bff
CREDENTIALS=/etc/admin-bff/credentials
UV=${UV:-/usr/local/bin/uv}

cd "$APP_DIR"

echo "==> git pull"
git pull --ff-only

echo "==> uv sync"
# --compile-bytecode: kod papkasi read-only, .pyc oldindan yaratiladi.
# Python 3.12 (.python-version). Ubuntu 22.04'da u paket sifatida yo'q (tizimniki
# 3.10), serverga alohida o'rnatiladi: /usr/local/bin/python3.12 (docs/deploy.md).
# Ichki tarmoqda tashqi yuklab olish yopiq, shuning uchun uv Python'ni
# hech qachon internetdan yuklamaydi: tizimda topilmasa, xato beradi.
# only-system: uv avval yuklab olgan Python /root ichida turadi, servis esa
# u yerni ko'rmaydi (ProtectHome=yes) va 203/EXEC bilan ishga tushmaydi.
UV_PYTHON_PREFERENCE=only-system UV_PYTHON_DOWNLOADS=never \
    "$UV" sync --frozen --no-dev --compile-bytecode

echo "==> alembic upgrade head"
# Migratsiyalar DB_USER nomidan bajariladi: production'da bitta DB user
# (egasining qarori, 2026-11-24). DB_OWNER_USER berilsa, ular sxema egasi
# nomidan bajariladi (parol: credentials/db_owner_password, u servisga
# berilmaydi) va DB_USER'ga audit jadvallarida faqat SELECT va INSERT qoladi
# (9-bo'lim, migrations/env.py).
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
