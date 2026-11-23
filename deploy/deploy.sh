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
# Python 3.12 (.python-version). Debian 13'da u paket sifatida yo'q, serverga
# alohida o'rnatiladi, masalan /usr/local/bin/python3.12 (README, "Talablar").
# Ichki tarmoqda tashqi yuklab olish yopiq, shuning uchun uv Python'ni
# hech qachon internetdan yuklamaydi: tizimda topilmasa, xato beradi.
UV_PYTHON_DOWNLOADS=never "$UV" sync --frozen --no-dev --compile-bytecode

echo "==> alembic upgrade head"
# Migratsiyalar DB egasi (DB_OWNER_USER, parol: credentials/db_owner_password)
# nomidan bajariladi. Keyin ilova roliga (DB_USER) huquqlar qaytadan beriladi:
# audit jadvallarida faqat SELECT va INSERT (9-bo'lim, migrations/env.py).
# db_owner_password servisga berilmaydi (admin-bff.service'da LoadCredential yo'q).
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
