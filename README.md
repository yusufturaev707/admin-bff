# UZBMB Admin BFF

Yagona adminka backend'i. Barcha ichki tizimlar (Face-ID davomat, proctoring,
ejournal, quloq dastur va keyin qo'shiladiganlar) shu BFF orqali bitta
adminkadan boshqariladi. Frontend faqat shu API bilan ishlaydi
(`/api/v1/openapi.json`, snapshot: `openapi/v1.json`).

Holat: **0-bosqich (skelet)**. Bosqichlar ro'yxati `CLAUDE.md`ning 12-bo'limida.

## Talablar

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL 16+ va Redis 7 (lokal o'rnatilgan, Docker ishlatilmaydi)

## Lokal ishga tushirish

```bash
uv sync                      # .venv yaratadi va dependency'larni o'rnatadi
cp .env.example .env         # kerak bo'lsa DB/Redis manzillarini o'zgartiring
uv run uvicorn --factory app.main:create_app --reload --port 8000
```

Tekshirish:

```bash
curl -i http://127.0.0.1:8000/health    # 200 {"status":"ok"}
curl -i http://127.0.0.1:8000/ready     # 200, DB yoki Redis ishlamasa 503
```

Production'dan tashqari muhitda OpenAPI sxemasi
`http://127.0.0.1:8000/api/v1/openapi.json` manzilida. Production'da u yopiq.

## Tekshiruvlar

Hammasi bitta skriptda, CI ham shuni ishlatadi:

```bash
bash scripts/ci.sh
```

Alohida:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict app/
uv run bandit -q -r app
uv run pip-audit
```

## OpenAPI snapshot

`openapi/v1.json` frontend bilan kontrakt. API o'zgarsa, test xato beradi.
O'zgarishni ko'rib chiqib, snapshot'ni yangilang:

```bash
uv run python -m app.cli export-openapi
```

Har bir endpoint'da aniq `operation_id` (`<system>_<resource>_<verb>`) bo'lishi
shart, aks holda ilova ishga tushmaydi.

## Sozlamalar

Sozlamalar environment o'zgaruvchilaridan olinadi (`app/settings.py`).
Development'da `.env` o'qiladi. Production'da (`$CREDENTIALS_DIRECTORY`
mavjud bo'lsa) `.env` umuman o'qilmaydi.

| O'zgaruvchi | Sukut | Izoh |
| --- | --- | --- |
| `APP_ENV` | `production` | `development`, `test`, `production` |
| `LOG_LEVEL` | `INFO` | |
| `LOG_FORMAT` | `json` | production'da faqat `json` |
| `FRONTEND_ORIGIN` | yo'q | CORS va CSRF uchun yagona ruxsat etilgan origin |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` | `127.0.0.1`, `5432`, `admin_bff`, `admin_bff` | `DB_HOST` unix socket papkasi ham bo'lishi mumkin |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | parol URL'da bo'lmasin |

Secret'lar (`db_password`, `redis_password`, keyin `totp_enc_key`,
`jwt_private_key`) production'da faqat systemd `LoadCredential=` orqali
beriladi. Kodga, testga va repo'ga yozilmaydi.

## Deploy (Debian, systemd, Docker'siz)

Fayllar `deploy/` papkasida:

| Fayl | Vazifasi |
| --- | --- |
| `admin-bff.service` | systemd unit (hardening, `LoadCredential=`, unix socket) |
| `gunicorn.conf.py` | Gunicorn + UvicornWorker, `/run/admin-bff/bff.sock` |
| `admin-bff.env.example` | `/etc/admin-bff/admin-bff.env` namunasi |
| `nginx/admin-api.conf` | API server bloki: TLS, HSTS, rate limit, SSE, `/internal/` yopiq |
| `nginx/admin-frontend.conf` | frontend server bloki |
| `nginx/admin-bff-internal.conf` | faqat `127.0.0.1`: JWKS va `/metrics` |
| `nginx/admin-allowlist.conf` | IP allowlist (sukut bo'yicha hammasi yopiq) |
| `deploy.sh` | `git pull`, `uv sync --frozen`, `alembic upgrade head`, `systemctl reload` |

Birinchi o'rnatish tartibi `admin-bff.service` faylining boshida yozilgan.
Yangilash:

```bash
sudo /opt/admin-bff/deploy/deploy.sh
```

## CLI

```bash
uv run python -m app.cli export-openapi [--check]
```

Keyingi bosqichlarda qo'shiladi: `create-superadmin`, `sync-permissions`,
`rotate-keys`, `verify-audit`.
