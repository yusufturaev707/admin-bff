# UZBMB Admin BFF

Yagona adminka backend'i. Barcha ichki tizimlar (Face-ID davomat, proctoring,
ejournal, quloq dastur va keyin qo'shiladiganlar) shu BFF orqali bitta
adminkadan boshqariladi. Frontend faqat shu API bilan ishlaydi
(`/api/v1/openapi.json`, snapshot: `openapi/v1.json`).

Holat: **3-bosqich (Audit)**. Bosqichlar ro'yxati `CLAUDE.md`ning 12-bo'limida.
Frontend uchun qo'llanma: [`docs/frontend.md`](docs/frontend.md), xavfsizlik:
[`docs/security.md`](docs/security.md).

## Talablar

- Python 3.12 (`.python-version`)
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL 16+ va Redis 7+ (lokal o'rnatilgan, Docker ishlatilmaydi)

Dependency'lar faqat `pyproject.toml` va `uv.lock`da, ular `uv sync` bilan
o'rnatiladi. `requirements.txt` yo'q.

Server: **Debian 12 (bookworm)**, boshqa tizim (proktoring) bilan umumiy.
Serverga o'rnatish tartibi: [`docs/deploy.md`](docs/deploy.md). Qisqacha:

- PostgreSQL: Debian'ning o'zida 15-versiya, u boshqa tizimniki. BFF uchun
  alohida PostgreSQL 17 klasteri (PGDG repo'si, port 5433) ishlatiladi.
- Redis: Debian'niki 7.0, mos keladi. BFF o'z instansini ishlatadi
  (`deploy/admin-bff-redis.service`), boshqa tizimning Redis'iga tegmaydi.
- nginx 1.22: `http2 on;` yo'q (u 1.25.1'dan beri), HTTP/2 yoqilmagan
  (`deploy/nginx/admin-api.conf` boshidagi izoh).

**Python 3.12 serverga alohida o'rnatiladi:** Debian 12'ning o'z Python'i
3.11, unga boshqa loyihalar bog'langan va u o'zgartirilmaydi.
`deploy.sh` Python'ni internetdan yuklamaydi
(`UV_PYTHON_DOWNLOADS=never`), uni tizimda `python3.12` nomi bilan qidiradi,
masalan `/usr/local/bin/python3.12` (manbadan `make altinstall`). Python
`/root` yoki boshqa uy papkasiga o'rnatilmasin: servis `ProtectHome=yes` bilan
ishlaydi va u yerni ko'rmaydi.

## Lokal ishga tushirish

```bash
uv sync                      # .venv yaratadi va dependency'larni o'rnatadi
cp .env.example .env         # DB/Redis manzillari, DB_PASSWORD, kalitlar
```

`.env`da `PINFL_HMAC_KEY` bo'lishi shart. U 32 baytli tasodifiy kalit
(base64), yaratish buyrug'i `.env.example`da yozilgan.
PostgreSQL'da `DB_USER` role'i bo'lishi kerak: `CREATEDB` huquqi bilan, chunki
testlar o'zlarining vaqtinchalik bazasini yaratadi.

```sql
CREATE ROLE admin_bff LOGIN CREATEDB PASSWORD '...';
CREATE DATABASE admin_bff OWNER admin_bff;
```

Development'da bitta rol yetarli. Bunda audit jadvallarini faqat trigger'lar
himoya qiladi, ilova esa ishga tushishda `audit_privileges_too_broad` deb
ogohlantiradi. Production'da ikkita rol shart (pastda, "PostgreSQL rollari").

```bash
uv run alembic upgrade head                                 # jadvallar
uv run python -m scripts.create_superadmin --username admin  # parol so'raladi
uv run uvicorn --factory app.main:create_app --reload --port 8000
```

`git pull`dan keyin har safar `uv run alembic upgrade head` bajariladi: baza
eskirgan bo'lsa, ilova ishga tushmaydi.

`permissions` jadvalini ilova ishga tushishda o'zi yangilaydi: koddagi
registry'ga (`app/rbac/permissions.py`) qarab yangi permission'larni qo'shadi,
tavsiflarni yangilaydi, e'lon qilinmaganlarini o'chiradi. Rollarga berilgan
huquqlarga (`role_permissions`) u tegmaydi.

Birinchi superadmin faqat shu skript bilan yaratiladi, HTTP orqali yaratish
yo'q (6-bo'lim). Parol terminalda ikki marta so'raladi, argument yoki
environment orqali berilmaydi. Yangi admin birinchi kirishda parolini
almashtiradi (`docs/frontend.md`, "Birinchi kirish"). Serverda ishga tushirish:
pastda, "Superadmin".

Tekshirish:

```bash
curl -i http://127.0.0.1:8000/health    # 200 {"status":"ok"}
curl -i http://127.0.0.1:8000/ready     # 200, DB yoki Redis ishlamasa 503
```

Production'dan tashqari muhitda OpenAPI sxemasi
`http://127.0.0.1:8000/api/v1/openapi.json`, Swagger UI esa
`http://127.0.0.1:8000/api/v1/docs` manzilida. Swagger assetlari lokal
(`app/static/swagger-ui/`, CDN ishlatilmaydi). Production'da ikkalasi faqat
`admin:api:docs` ruxsati bor adminga ochiladi.

## Tekshiruvlar

Testlar lokal PostgreSQL va Redis'da ishlaydi.

- **PostgreSQL.** Har bir test sessiyasi `admin_bff_test_<tasodifiy>`
  bazasini yaratadi, unga migratsiyalarni qo'llaydi va oxirida o'chiradi.
  Ulanish uchun `.env` yoki environment'dagi `DB_*` sozlamalari olinadi.
- **Redis.** Lokal Redis boshqa loyihalar bilan umumiy bo'lishi mumkin,
  shuning uchun testlar `FLUSHDB` qilmaydi. Ular tasodifiy prefiksli
  kalitlarni yaratadi va faqat shularni o'chiradi. Boshqa Redis kerak bo'lsa,
  `TEST_REDIS_URL` bering.
- **Audit huquqlari testi.** `tests/audit/test_privileges.py` vaqtinchalik
  ilova rolini yaratadi va oxirida o'chiradi. Buning uchun `DB_USER`da
  `CREATEROLE` bo'lishi kerak. Bo'lmasa, bu testlar "skipped"
  bo'lib o'tadi. Ularni o'tkazib yubormang:
  `ALTER ROLE admin_bff CREATEROLE;`

CI yo'q (egasining qarori, 2026-11-23), tekshiruvlar qo'lda ishga
tushiriladi:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict app/ tests/ scripts/
uv run bandit -q -r app
uv run pip-audit
```

## OpenAPI snapshot

`openapi/v1.json` frontend bilan kontrakt. API o'zgarsa, test xato beradi.
O'zgarishni ko'rib chiqib, snapshot'ni yangilang:

```bash
UPDATE_OPENAPI_SNAPSHOT=1 uv run pytest tests/api/test_openapi.py
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
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` | `127.0.0.1`, `5432`, `admin_bff`, `admin_bff` | `DB_HOST` unix socket papkasi ham bo'lishi mumkin. `DB_USER` servisning roli |
| `DB_OWNER_USER` | yo'q | sxema egasi, faqat migratsiyalar uchun. Yo'q bo'lsa, `DB_USER` |
| `AUDIT_RETENTION_DAYS` | `90` | audit log saqlash muddati, kamida 90 |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | parol URL'da bo'lmasin |
| `REDIS_KEY_PREFIX` | bo'sh | umumiy dev Redis'da kalitlar aralashmasligi uchun |
| `SESSION_IDLE_TIMEOUT_S`, `SESSION_ABSOLUTE_TIMEOUT_S` | `1800`, `43200` | sessiya: 30 daqiqa harakatsizlik, 12 soat jami |
| `SESSION_REQUESTS_PER_MINUTE` | `300` | bitta sessiyadan daqiqasiga so'rovlar soni, oshsa `429` |
| `ARGON2_TIME_COST`, `ARGON2_MEMORY_COST_KIB`, `ARGON2_PARALLELISM` | `3`, `65536`, `4` | production'da kamida m=19 MiB, t=2 |
| `ARGON2_MAX_CONCURRENCY` | `1` | bitta worker'da bir vaqtda nechta Argon2 tekshiruvi. Har biri `ARGON2_MEMORY_COST_KIB` xotira oladi, hisob `deploy/gunicorn.conf.py`da |
| `GUNICORN_WORKERS` | `min(CPU, 4)` | worker'lar soni. Oshirilsa, `MemoryMax` ham oshiriladi (`deploy/gunicorn.conf.py`) |
| `ONEID_ENABLED` | `false` | OneID shablon, client hali yozilmagan (`app/auth/oneid.py`) |

Secret'lar production'da faqat systemd `LoadCredential=` orqali beriladi. Kodga,
testga va repo'ga yozilmaydi. Ular:

- `db_password` va `redis_password`;
- `db_owner_password`: faqat `deploy.sh` migratsiyalar uchun o'qiydi, servisga
  berilmaydi;
- `pinfl_hmac_key`: OneID'da PINFL bo'yicha qidirish kaliti;
- keyingi bosqichlarda `jwt_private_key` va `oneid_client_secret`.

## Deploy (Debian, systemd, Docker'siz)

Fayllar `deploy/` papkasida:

| Fayl | Vazifasi |
| --- | --- |
| `admin-bff.service` | systemd unit (hardening, `LoadCredential=`, unix socket) |
| `gunicorn.conf.py` | Gunicorn + `uvicorn_worker.UvicornWorker`, `/run/admin-bff/bff.sock`, Prometheus multiprocess fayllari |
| `admin-bff.env.example` | `/etc/admin-bff/admin-bff.env` namunasi |
| `admin-bff-redis.service`, `admin-bff-redis.conf` | BFF'ning alohida sessiya Redis'i (faqat unix socket, `requirepass`) |
| `nginx/admin-api.conf` | API server bloki: TLS, HSTS, rate limit, SSE, `/internal/` yopiq |
| `nginx/admin-frontend.conf` | frontend server bloki |
| `nginx/admin-bff-internal.conf` | faqat `127.0.0.1`: JWKS va `/metrics` |
| `nginx/admin-allowlist.conf` | IP allowlist (sukut bo'yicha hammasi yopiq) |
| `deploy.sh` | `git pull`, `uv sync --frozen`, `alembic upgrade head`, `systemctl reload` |

Birinchi o'rnatish tartibi: [`docs/deploy.md`](docs/deploy.md).

### Superadmin

Birinchi superadmin migratsiyalardan keyin serverda yaratiladi. Skript
servisning sozlamalari va credential'lari bilan root sifatida ishlaydi (xuddi
`deploy.sh` kabi):

```bash
sudo sh -c 'set -a; . /etc/admin-bff/admin-bff.env; set +a; cd /srv/admin-bff &&
  APP_ENV=production CREDENTIALS_DIRECTORY=/etc/admin-bff/credentials \
  .venv/bin/python -m scripts.create_superadmin --username <login>'
```

- `superadmin` tizim roli (`*:*:*`) bo'lmasa, skript uni yaratadi.
- Yaratish audit'ga yoziladi: actor `script`, `details.os_user`da buyruqni
  kim bajargani.
- Barcha superadminlar bloklanib qolsa ham, shu skript bilan yangi superadmin
  yaratiladi.

### Metrikalar

Prometheus metrikalari `/metrics` manzilida. Ular tashqaridan yopiq, faqat
serverning o'zidan ochiladi: `http://127.0.0.1:8081/metrics`
(`nginx/admin-bff-internal.conf`). Ularda quyidagilar bor:

- HTTP so'rovlar soni va davomiyligi, route shabloni bo'yicha;
- muvaffaqiyatsiz login'lar va bloklanishlar;
- rate limit'ga tushgan so'rovlar;
- DB'ga yozilmay qolgan audit hodisalari.

Tizimlar bo'yicha kechikish va circuit breaker metrikalari connector'lar
bilan birga qo'shiladi (5-bosqich).

### PostgreSQL rollari

Servis audit log'ni o'zgartira olmasligi uchun ikkita rol kerak (9-bo'lim):

- `admin_bff_owner` sxema egasi. Migratsiyalar shu rol nomidan bajariladi.
  Paroli `/etc/admin-bff/credentials/db_owner_password` faylida turadi va
  faqat `deploy.sh`ga kerak.
- `admin_bff` servisning o'zi. Audit jadvallarida faqat `SELECT` va `INSERT`
  qila oladi.

```sql
CREATE ROLE admin_bff_owner LOGIN PASSWORD '...';
CREATE ROLE admin_bff LOGIN PASSWORD '...';
CREATE DATABASE admin_bff OWNER admin_bff_owner;
-- Serverdagi boshqa tizimlarning rollari bu bazaga ulana olmasin:
REVOKE CONNECT, TEMPORARY ON DATABASE admin_bff FROM PUBLIC;
GRANT CONNECT ON DATABASE admin_bff TO admin_bff_owner, admin_bff;
```

`pg_hba.conf`: `local admin_bff admin_bff_owner,admin_bff scram-sha-256`.

`alembic upgrade head` har safar `admin_bff` roliga huquqlarni qaytadan beradi
(`app/core/db_privileges.py`). Yangi jadval avtomatik to'liq huquq oladi,
ortiqcha berilgan huquq esa olib tashlanadi. Production'da servis ishga
tushishda o'z huquqlarini tekshiradi. Agar u audit log'ni o'zgartira olsa
(masalan, `DB_USER` owner yoki superuser bo'lsa), servis ishga tushmaydi.
Yangilash:

```bash
sudo /srv/admin-bff/deploy/deploy.sh
```

## Kalitlar

Kalitlarni saqlash, zaxiralash va rotatsiya qilish tartibi:
[`docs/security.md`](docs/security.md).
