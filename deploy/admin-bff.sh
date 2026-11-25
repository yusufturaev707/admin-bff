#!/usr/bin/env bash
# Admin BFF'ni serverda boshqarish uchun qisqa buyruq. O'rnatish (bir marta):
#   ln -sf /srv/admin-bff/deploy/admin-bff.sh /usr/local/bin/admin-bff
#
# Sozlamalar va secret'lar servisdagidek olinadi: /etc/admin-bff/admin-bff.env
# va /etc/admin-bff/credentials/. Root sifatida ishga tushiriladi.
set -euo pipefail

APP_DIR=/srv/admin-bff
ENV_FILE=/etc/admin-bff/admin-bff.env
CREDENTIALS=/etc/admin-bff/credentials

usage() {
    cat <<'EOF'
Foydalanish:
  admin-bff update             yangi kodni o'rnatish (git pull, migratsiyalar, reload)
  admin-bff migrate            faqat migratsiyalar
  admin-bff superadmin LOGIN   yangi superadmin (parol so'raladi)
  admin-bff verify-audit       audit log butunligini tekshirish
  admin-bff status             servislar holati va /ready
EOF
}

# Buyruqni servisning sozlamalari va secret'lari bilan bajaradi.
with_settings() (
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    cd "$APP_DIR"
    exec env APP_ENV=production CREDENTIALS_DIRECTORY="$CREDENTIALS" "$@"
)

case "${1:-}" in
    "" | help | -h | --help)
        usage
        exit 0
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "root sifatida ishga tushiring: sudo admin-bff $*" >&2
    exit 1
fi

case "$1" in
    update)
        exec bash "$APP_DIR/deploy/deploy.sh"
        ;;
    migrate)
        with_settings .venv/bin/alembic upgrade head
        with_settings .venv/bin/alembic current
        ;;
    superadmin)
        if [ -z "${2:-}" ]; then
            echo "login kerak: admin-bff superadmin <login>" >&2
            exit 2
        fi
        with_settings .venv/bin/python -m scripts.create_superadmin --username "$2"
        ;;
    verify-audit)
        # journald'dagi eng yangi audit yozuvi (id va hash). Zanjir oxiridan
        # yozuvlar o'chirilsa, u bazada bo'lmaydi (scripts/verify_audit.py).
        last=$(journalctl -u admin-bff -o cat --no-pager --reverse |
            grep -F '"event": "audit"' | grep -m 1 -F '"audit_id"' || true)
        id=$(printf '%s' "$last" | grep -o '"audit_id": [0-9]*' | grep -o '[0-9]*$' || true)
        hash=$(printf '%s' "$last" | grep -o '"hash": "[0-9a-f]\{64\}"' |
            grep -o '[0-9a-f]\{64\}' || true)
        if [ -n "$id" ] && [ -n "$hash" ]; then
            with_settings .venv/bin/python -m scripts.verify_audit \
                --journal-id "$id" --journal-hash "$hash"
        else
            echo "journald'da audit yozuvi topilmadi." >&2
            with_settings .venv/bin/python -m scripts.verify_audit
        fi
        ;;
    status)
        for unit in admin-bff admin-bff-redis; do
            printf '%-16s %s\n' "$unit" "$(systemctl is-active "$unit" || true)"
        done
        printf '%-16s ' ready
        curl --silent --unix-socket /run/admin-bff/bff.sock http://localhost/ready ||
            printf "javob yo'q"
        echo
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
