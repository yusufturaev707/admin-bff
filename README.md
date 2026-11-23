# UZBMB Admin BFF

Yagona adminka backend'i. Barcha ichki tizimlar (Face-ID davomat, proctoring,
ejournal, quloq dastur va keyin qo'shiladiganlar) shu BFF orqali bitta
adminkadan boshqariladi. Frontend faqat shu API bilan ishlaydi
(`/api/v1/openapi.json`, snapshot: `openapi/v1.json`).

Holat: **2-bosqich (RBAC)**. Bosqichlar ro'yxati `CLAUDE.md`ning 12-bo'limida.
Frontend uchun qo'llanma: [`docs/frontend.md`](docs/frontend.md).

## Talablar

- Python 3.13 (`.python-version`)
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL 16+ va Redis 7+ (lokal o'rnatilgan, Docker ishlatilmaydi)

Serverlar: **Debian 13 (trixie)**. Uning paketlari talablarga mos keladi:
Python 3.13, PostgreSQL 17 va nginx 1.26. `http2 on;` sintaksisi nginx
1.25.1'dan beri ishlaydi. Redis versiyasini o'rnatishdan oldin
`apt policy redis-server` bilan tekshiring, kamida 7 bo'lishi kerak.
Python serverga alohida o'rnatilmaydi, tizimdagi `python3.13` ishlatiladi.

## Lokal ishga tushirish

```bash
uv sync                      # .venv yaratadi va dependency'larni o'rnatadi
cp .env.example .env         # DB/Redis manzillari, DB_PASSWORD, kalitlar
```

`.env`da `TOTP_ENC_KEY` va `PINFL_HMAC_KEY` bo'lishi shart. Ular 32 baytli
tasodifiy kalitlar (base64), yaratish buyrug'i `.env.example`da yozilgan.
PostgreSQL'da `DB_USER` role'i bo'lishi kerak: `CREATEDB` huquqi bilan, chunki
testlar o'zlarining vaqtinchalik bazasini yaratadi.

```sql
CREATE ROLE admin_bff LOGIN CREATEDB PASSWORD '...';
CREATE DATABASE admin_bff OWNER admin_bff;
```

```bash
uv run alembic upgrade head                                 # jadvallar
uv run python -m app.cli sync-permissions                    # permission'lar
uv run python -m app.cli create-superadmin --username admin # parol so'raladi
uv run uvicorn --factory app.main:create_app --reload --port 8000
```

Birinchi kirishda admin TOTP'ni ulaydi va parolini almashtiradi
(`docs/frontend.md`, "Birinchi kirish").

Tekshirish:

```bash
curl -i http://127.0.0.1:8000/health    # 200 {"status":"ok"}
curl -i http://127.0.0.1:8000/ready     # 200, DB yoki Redis ishlamasa 503
```

Production'dan tashqari muhitda OpenAPI sxemasi
`http://127.0.0.1:8000/api/v1/openapi.json` manzilida. Production'da u yopiq.

## Tekshiruvlar

Testlar lokal PostgreSQL va Redis'da ishlaydi.

- **PostgreSQL.** Har bir test sessiyasi `admin_bff_test_<tasodifiy>`
  bazasini yaratadi, unga migratsiyalarni qo'llaydi va oxirida o'chiradi.
  Ulanish uchun `.env` yoki environment'dagi `DB_*` sozlamalari olinadi.
- **Redis.** Lokal Redis boshqa loyihalar bilan umumiy bo'lishi mumkin,
  shuning uchun testlar `FLUSHDB` qilmaydi. Ular tasodifiy prefiksli
  kalitlarni yaratadi va faqat shularni o'chiradi. Boshqa Redis kerak bo'lsa,
  `TEST_REDIS_URL` bering.

Hammasi bitta skriptda, CI ham shuni ishlatadi:

```bash
bash scripts/ci.sh
```

CI: GitHub Actions (`.github/workflows/ci.yml`) shu skriptni `master`'ga har
bir push'da va har bir Pull Request'da ishga tushiradi.

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
| `REDIS_KEY_PREFIX` | bo'sh | umumiy dev Redis'da kalitlar aralashmasligi uchun |
| `SESSION_IDLE_TIMEOUT_S`, `SESSION_ABSOLUTE_TIMEOUT_S` | `1800`, `43200` | sessiya: 30 daqiqa harakatsizlik, 12 soat jami |
| `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST_KIB`, `ARGON2_PARALLELISM` | `3`, `65536`, `4` | production'da kamida m=19 MiB, t=2 |
| `TOTP_ISSUER` | `UZBMB Admin` | autentifikator ilovasida ko'rinadigan nom |
| `ONEID_ENABLED` | `false` | OneID shablon, client hali yozilmagan (`app/auth/oneid.py`) |

Secret'lar production'da faqat systemd `LoadCredential=` orqali beriladi. Kodga,
testga va repo'ga yozilmaydi. Ular:

- `db_password` va `redis_password`;
- `totp_enc_key`: TOTP secret'larini AES-GCM bilan shifrlash kaliti;
- `pinfl_hmac_key`: OneID'da PINFL bo'yicha qidirish kaliti;
- keyingi bosqichlarda `jwt_private_key` va `oneid_client_secret`.

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
uv run python -m app.cli create-superadmin --username <login>   # parol interaktiv so'raladi
uv run python -m app.cli create-superadmin --username <login> --existing  # mavjudini superadmin qilish
uv run python -m app.cli sync-permissions                       # har deploy'da (deploy.sh)
uv run python -m app.cli unlock-login --username <login> [--ip <ip>]
uv run python -m app.cli reencrypt-totp                          # TOTP_ENC_KEY rotatsiyasidan keyin
uv run python -m app.cli reset-totp --username <login>           # yoki --all --yes (kalit yo'qolsa)
```

Kalitlarni saqlash, zaxiralash va rotatsiya qilish tartibi:
[`docs/security.md`](docs/security.md).

Keyingi bosqichlarda qo'shiladi: `rotate-keys`, `verify-audit`.
