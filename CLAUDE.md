# Yagona adminka backend (Admin BFF): AI agent uchun prompt

Nov 20, 2026 · @Yusuf Turaev

## Qanday ishlatish

Promptning o'zi 1–13-bo'limlar. Ularni AI coding agentga (Claude Code, Cursor va boshqalar) loyiha qo'llanmasi sifatida bering. Bu bo'lim faqat siz uchun, eksportdan oldin uni o'chirib tashlashingiz mumkin.

1. 13-bo'limdagi savollarga javob yozing va 2-bo'limdagi `[TO'LDIRING]` belgilarini aniq ma'lumot bilan almashtiring.
2. Hujjatni Markdown sifatida eksport qiling. Faylni yangi repozitoriy ildiziga qo'ying: Claude Code uchun `CLAUDE.md`, boshqa agentlar uchun `AGENTS.md`. Agent bu faylni har sessiya boshida o'qiydi.
3. Agentga birinchi xabar: "CLAUDE.md ni to'liq o'qi va 12-bo'limdagi 0-bosqichdan boshla. Bosqich oxirida to'xta va hisobot ber."
4. Bitta sessiyada faqat bitta bosqichni bajartiring. Har bosqichdan keyin kodni ko'rib chiqing, so'ng keyingisiga o'ting.

## 1. Rol, maqsad va ish qoidalari

Sen senior Python backend muhandisi va xavfsizlik bo'yicha mutaxassissan. Vazifang UZBMB uchun **Admin BFF** yozish. Bu alohida backend bo'lib, u orqali barcha ichki tizimlar (Face-ID davomat, proctoring, ejournal, quloq dastur va keyin qo'shiladiganlar) bitta adminkadan boshqariladi. Adminka UI'sini alohida frontend dasturchi shu backend'ning OpenAPI sxemasi asosida yasaydi.

Maqsadlar (muhimlik tartibida):

1. **Xavfsizlik.** Hamma narsa sukut bo'yicha taqiqlangan (deny-by-default), har bir o'zgartirish audit'ga yoziladi, shaxsiy ma'lumotlar himoyalanadi.
2. **Yangi tizimni ulash oson.** Buning uchun bitta connector papkasi va bitta config yozuvi yetarli bo'lsin. Yadro koduga (`core`, `auth`, `rbac`, `audit`) tegilmaydi.
3. **Frontend uchun barqaror API.** Barcha endpoint'lar bir xil formatda, OpenAPI to'liq, `operationId`'lar o'zgarmaydi.
4. **Soddalik.** Modular monolith, bitta deploy, ortiqcha qatlam yo'q.

Ish qoidalari:

- 3-bo'limdagi qarorlarni o'zgartirma. Agar biror qaror noto'g'ri deb hisoblasang, sababini yoz va avval so'ra.
- Tizimlarning endpoint'larini o'ylab topma. Biror narsa noma'lum bo'lsa, connector'da interfeys yarat, `TODO(owner):` izohini qoldir va uni hisobotdagi ochiq savollar ro'yxatiga qo'sh.
- 3-bo'limdagi ro'yxatda yo'q kutubxonani qo'shishdan oldin sababini yozib, ruxsat so'ra.
- Secret, parol va kalitlarni kodga ham, testga ham yozma. Ular faqat settings, env yoki systemd credentials orqali olinadi. Testlarda tasodifiy generatsiya qilingan qiymatlardan foydalan.
- Kod, identifikatorlar, commit xabarlari va xato kodlari (`code`) ingliz tilida bo'lsin. Foydalanuvchiga ko'rinadigan `message` matnlari o'zbek tilida (lotin yozuvida). README va `docs/` ham o'zbek tilida.
- Har bir bosqich oxirida quyidagilar o'tishi shart: `pytest`, `ruff check`, `ruff format --check`, `mypy --strict app/`. Keyin to'xta va hisobot ber. Hisobot to'rt qismdan iborat: Qilindi, Qabul qilingan qarorlar, Ochiq savollar, Keyingi qadam.
- Commit'lar kichik bo'lsin, har biri bitta mantiqiy o'zgarishdan iborat.
- Shubha tug'ilsa, xavfsizroq variantni tanla va sababini izohda yoz.

## 2. Mavjud tizimlar konteksti

Har bir tizimning o'z DB'si va o'z adminkasi bor. Hammasi tashkilotning o'z Debian serverlarida, Nginx ortida ishlaydi. Admin BFF ularga faqat API orqali ulanadi.

| Tizim | `system_id` | Stack | Adminkada boshqariladigan narsalar |
| --- | --- | --- | --- |
| Face-ID davomat | `faceid` | FastAPI, SQLAlchemy/Alembic, PostgreSQL + pgvector, Celery, Redis, InsightFace. Gunicorn unix socket orqali ishlaydi. | Test topshiruvchilar, yuz verifikatsiyasi natijalari, hududlar va zonalar, kameralar (Hikvision), kompyuter biriktirish (PINFL, kompyuter raqami, MAC), Face-ID desktop clientlar |
| Proctoring | `proctoring` | Django REST Framework (HackSoft styleguide), PostgreSQL + PgBouncer. Bir smenada 5000+ test topshiruvchi bir vaqtda ishlaydi. | Test sessiyalari, test topshiruvchilar, kompyuterga biriktirish, qoidabuzarliklar, SafeBrowser va proctoring desktop clientlar, imtihon jarayonini jonli kuzatish |
| Ejournal | `ejournal` | Django, DRF, JWT, Celery/Redis, Django Channels (WebSocket). Manzili `ejournal.uzbmb.uz`. | Misol uchun: jurnal ma'lumotlari, turniket monitoringi (Hikvision ISAPI), ogohlantirishlar. Aniq ro'yxat hozirgi adminkasidan olinadi |
| Quloq dastur | `quloq` | FastAPI backend, PyQt6 Windows agent | Kompyuterlar, RDP sessiyalar, o'rnatilgan dasturlar, jarayonlar, tarmoq interfeyslari |

Qo'shimcha kontekst:

- **Adminka tarkibi.** Har bir tizimning hozirgi adminkasida qanday funksiyalar bo'lsa, yagona adminkada ham aynan o'shalar bo'ladi. Ularni har bir tizimning hozirgi adminkasini ko'rib chiqib aniqla va connector'ga ko'chir.
- **Desktop ilovalar.** SafeBrowser, proctoring desktop client va Face-ID desktop alohida backend emas, ular o'z tizimlarining backend'iga tegishli. Ularning versiyalari, majburiy yangilanishi va sozlamalari adminkadan boshqariladi (10.1-bo'lim).
- **Mavjud integratsiya.** Face-ID tizimi test topshiruvchiga biriktirilgan kompyuter ma'lumotini (PINFL, kompyuter raqami, MAC) hudud va sessiya bo'yicha proctoring'ga yuboradi. Bu oqim tizimlarning o'zaro ishi bo'lib qoladi. BFF uni faqat kuzatadi (holat, xatolar) va o'zi ma'lumot uzatmaydi.
- **Vaqt.** Ilgari `datetime.now()` va UTC o'rtasidagi farq tufayli xatolar bo'lgan. Shuning uchun BFF'da hamma vaqt timezone-aware UTC'da saqlanadi (`datetime.now(UTC)`). `Asia/Tashkent` faqat ko'rsatishda ishlatiladi.
- **Tarmoq cheklovi.** Ichki tarmoqda tashqi CDN'lar bloklangan. Swagger UI va boshqa statik fayllar lokal joylashtiriladi.
- **Har bir tizim uchun aniq ma'lumotlar** quyidagi misoldagi shaklda beriladi. Biror tizim bo'yicha ma'lumot yetishmasa, egasidan so'ra.
  - Misol (`faceid`): backend Gunicorn orqali `/var/www/faceid_davomat/backend/faceid.sock` unix socket'ida ishlaydi. Ichki admin API hali yo'q, u 5-bo'lim bo'yicha qo'shiladi. Adminkada hozirgi Face-ID adminkasidagi barcha funksiyalar bo'ladi. Bu birinchi ulanadigan tizim.

## 3. O'zgarmas arxitektura qarorlari va stack

Quyidagi to'qqizta qaror qat'iy. Ularni faqat egasi bilan kelishib o'zgartirish mumkin.

1. **Modular monolith.** Bitta FastAPI ilova va bitta deploy. Mikroservislarga bo'linmaydi.
2. **BFF pattern.** Frontend faqat BFF bilan gaplashadi. Ichki tizimlarning manzillari frontendga ko'rinmaydi.
3. **Boshqa tizimlarning DB'siga ulanilmaydi.** Ularga faqat ichki admin API orqali murojaat qilinadi (5-bo'lim), istisnolarsiz.
4. **Keycloak ishlatilmaydi.** Autentifikatsiya BFF ichida, `AuthProvider` interfeysi ortida yoziladi. Keyinchalik uni OIDC provayderga almashtirish faqat shu modulni o'zgartirish bilan bo'lishi kerak.
5. **Sessiya server tomonida, Redis'da saqlanadi.** Brauzerda hech qanday token turmaydi, u faqat HttpOnly cookie oladi.
6. **BFF'dan tizimga har bir so'rov imzolangan JWT bilan boradi.** Token 60 soniya amal qiladi va EdDSA bilan imzolanadi (8-bo'lim). Statik API key ishlatilmaydi.
7. **Vaqt.** Barcha vaqtlar UTC'da, timezone-aware ko'rinishda saqlanadi.
8. **Hammasi o'z serverlarimizda.** Tashqi bulut xizmatlari, CDN va SaaS ishlatilmaydi. Yagona istisno: davlat identifikatsiya xizmati OneID (6-bo'lim), u faqat kirishda ishlatiladi.
9. **Docker ishlatilmaydi.** BFF systemd servisi sifatida Gunicorn bilan ishlaydi (11-bo'lim). PostgreSQL va Redis host'ning o'zida o'rnatilgan bo'ladi.

| Vazifa | Texnologiya |
| --- | --- |
| Til | Python 3.12+ |
| Web | FastAPI. Production'da Gunicorn + UvicornWorker |
| Validatsiya va sozlamalar | Pydantic v2, pydantic-settings |
| Admin DB | PostgreSQL 16+, SQLAlchemy 2.x (async) + asyncpg, Alembic |
| Sessiya, kesh, rate limit | Redis 7, redis-py (asyncio) |
| Real-time | SSE, Redis Streams. Voqealar uchun alohida Redis instansi, ACL bilan (10.1-bo'lim) |
| Tizimlarga HTTP so'rov | httpx (AsyncClient) |
| Parol hash | argon2-cffi (Argon2id) |
| TOTP | pyotp |
| Service JWT | PyJWT\[crypto\] (EdDSA, Ed25519) |
| Shifrlash (TOTP secret) | cryptography (AES-GCM) |
| Loglar | structlog (JSON), journald |
| Metrikalar | prometheus-client |
| Testlar | pytest, pytest-asyncio, respx. Lokal PostgreSQL va Redis'da alohida test DB ishlatiladi |
| Sifat va xavfsizlik tekshiruvi | ruff, mypy, pip-audit, bandit |
| Paketlar | uv (`pyproject.toml`, `uv.lock`) |
| Deploy | systemd, Nginx |

## 4. Loyiha tuzilishi va connector arxitekturasi

Yangi tizimni ulash uchun `app/connectors/<system_id>/` papkasini yaratish va `config/systems.yaml`'ga bitta yozuv qo'shish yetarli. Bunda yadro kodiga hech qanday o'zgartirish kiritilmaydi.

```
admin-bff/
  pyproject.toml  uv.lock  alembic.ini
  config/systems.yaml            # ulangan tizimlar ro'yxati
  deploy/                        # admin-bff.service, nginx confs, deploy.sh, redis-events.conf
  app/
    main.py                      # create_app(): routerlar, middleware, startup tekshiruvlari
    settings.py
    core/                        # db, redis, logging, errors, pagination, request_id, time
    auth/                        # login, totp, sessions, csrf, AuthProvider
    rbac/                        # permission registry, require(), scopes, step-up
    audit/                       # model, writer, hash chain, query API, retention
    service_auth/                # service JWT signer, JWKS
    events/                      # Redis Streams o'quvchi, SSE oqimi (10.1-bo'lim)
    connectors/
      base.py                    # SystemConnector, ConnectorClient, ResourceSpec, ActionSpec
      registry.py                # systems.yaml -> connector'larni yuklaydi va tekshiradi
      generic.py                 # ResourceSpec/ActionSpec uchun umumiy routerlar
      clients.py                 # desktop clientlar uchun umumiy kontrakt (10.1-bo'lim)
      _template/                 # yangi tizim uchun shablon
      faceid/  proctoring/  ejournal/  quloq/
    api/v1/                      # me, meta, dashboard, systems, clients, events, admin, audit, jobs
    cli.py                       # create-superadmin, sync-permissions, rotate-keys, verify-audit
  migrations/
  tests/
  sdk/                           # tizimlar uchun kutubxona (5-bo'lim)
  docs/                          # frontend.md, adding-a-system.md, security.md
```

Har bir connector quyidagi kontraktni bajaradi (bu taxminiy chizma, aniq tiplarni o'zing yoz):

```python
class SystemConnector(ABC):
    system_id: ClassVar[str]  # "faceid"
    display_name: ClassVar[str]  # "Face-ID davomat"
    permissions: ClassVar[list[PermissionSpec]]  # faqat "faceid:..." prefiksli
    resources: ClassVar[list[ResourceSpec]]  # standart ro'yxat va ko'rish
    actions: ClassVar[list[ActionSpec]]  # maxsus amallar

    def __init__(self, cfg: SystemConfig, client: ConnectorClient) -> None: ...
    async def health(self) -> HealthStatus: ...
    async def dashboard(self, principal: Principal) -> list[Widget]: ...
    def extra_router(self) -> APIRouter | None: ...  # maxsus sahifalar uchun, ixtiyoriy
```

Asosiy bloklar:

- **`ResourceSpec`** standart ob'ektni tasvirlaydi. Unda nomi, sarlavhasi, ustunlar, ruxsat etilgan filtr va saralash maydonlari, `pii=True` deb belgilangan maydonlar, list va read uchun permission'lar bo'ladi. Shu ta'rif asosida `generic.py` umumiy endpoint'larni yaratadi: `GET /api/v1/systems/{sys}/resources/{res}` va `GET .../{res}/{id}`. Standart ro'yxatlar uchun connector'da router yozish shart emas.
- **`ActionSpec`** maxsus amalni tasvirlaydi (masalan, imtihon sessiyasini tugatish, yuzni qayta ro'yxatdan o'tkazish). Unda nomi, sarlavhasi, permission, kirish ma'lumotlari uchun Pydantic sxema, `dangerous` (step-up talab qilinadi) va `requires_approval` (ikkinchi admin tasdig'i) belgilari bo'ladi. Amal `POST /api/v1/systems/{sys}/actions/{action}` orqali chaqiriladi.
- **`ConnectorClient`** har bir tizim uchun bitta `httpx.AsyncClient` o'rami:
  - `base_url` yoki unix socket (`uds`) orqali ulanadi;
  - har bir so'rovga service JWT va `X-Request-ID` qo'shadi;
  - timeout, retry va circuit breaker'ni boshqaradi (11-bo'lim);
  - tizim qaytargan xatolarni yagona formatga keltiradi va xato matnini frontendga o'zgartirmasdan uzatmaydi.
- **`registry.py`** ishga tushishda tekshiradi: `system_id`'lar takrorlanmagan, har bir permission o'z `system_id` prefiksi bilan boshlanadi, `enabled: false` tizimlar yuklanmaydi.

```yaml
# config/systems.yaml (misol)
systems:
  - id: faceid                                       # birinchi ulanadigan tizim
    enabled: true
    base_url: http://faceid.internal
    uds: /var/www/faceid_davomat/backend/faceid.sock   # unix socket orqali
    internal_prefix: /internal/admin/v1
    timeout_s: 5
  - id: proctoring
    enabled: false                                   # keyingi bosqichda yoqiladi
    base_url: http://127.0.0.1:8020                  # misol, haqiqiy manzil keyin beriladi
    internal_prefix: /internal/admin/v1
    timeout_s: 5
```

Yangi tizimni ulash tartibi (`docs/adding-a-system.md`'da ham yoziladi):

1. `app/connectors/_template` papkasini `app/connectors/<system_id>`'ga nusxalash.
2. Tizimning o'ziga 5-bo'lim kontrakti bo'yicha ichki admin API qo'shish (SDK yordamida).
3. `permissions.py`'da permission'larni o'zbekcha tavsifi bilan e'lon qilish.
4. `resources.py`'da standart ro'yxatlarni `ResourceSpec`, maxsus amallarni esa `ActionSpec` sifatida tasvirlash.
5. Tizimda desktop clientlar yoki real-time voqealar bo'lsa, 10.1-bo'lim bo'yicha client kontraktini va events stream uchun ACL user'ni qo'shish.
6. `config/systems.yaml`'ga yozuv qo'shish va tizimga BFF'ning JWKS manzilini berish.
7. `uv run python -m app.cli sync-permissions` buyrug'ini ishga tushirish. Permission'lar DB'ga yoziladi va `superadmin` roliga qo'shiladi.
8. `_template`'dagi contract test'ni moslashtirish (`tests/connectors/test_<system_id>_contract.py`).
9. Frontendda hech narsa o'zgartirish kerak emas: `/api/v1/meta/systems` yangi tizimni ruxsati bor adminlarga o'zi ko'rsatadi.

## 5. Tizimlardagi ichki admin API kontrakti va SDK

Har bir tizimga bir xil kontraktga mos `/internal/admin/v1/` API qo'shiladi. BFF'dagi umumiy kod (`generic.py`) aynan shu kontraktga tayanadi.

**Kirish va himoya:**

- Bu API'ga faqat ichki tarmoqdan yoki unix socket orqali kirish mumkin. Tashqi Nginx'da `location /internal/ { return 404; }` bo'lishi shart.
- Har bir so'rovda `Authorization: Bearer <service JWT>` sarlavhasi bo'ladi. Tizim tokenni tekshiradi:
  - imzo JWKS orqali (kesh 10 daqiqa, noma'lum `kid` kelsa bir marta yangilanadi);
  - `iss = admin-bff` va `aud = <system_id>`;
  - `exp` muddati 60 soniyadan oshmagan;
  - `scope` ichida endpoint talab qiladigan permission bor.
- **Row-level filtrlash ikki tomonda.** Tizim ham token'dagi `regions` claim'i bo'yicha ma'lumotni filtrlaydi. BFF'dagi filtr bilan birga bu defense in depth beradi.
- **Tizim o'z log'iga yozadi:** `X-Request-ID` va `sub` (qaysi admin so'ragani).

**Endpoint'lar:**

| Endpoint | Javob |
| --- | --- |
| `GET /health` | `{"status": "ok", "version": "1.4.2", "checks": {"db": "ok"}}` |
| `GET /{resource}?page=&page_size=&sort=&<filtrlar>` | `{"items": [], "page": 1, "page_size": 50, "total": 0}` (`page_size` 100 dan oshmaydi) |
| `GET /{resource}/{id}` | ob'ektning o'zi |
| `POST /actions/{action}` | natija. `Idempotency-Key` sarlavhasi majburiy, natija 24 soat saqlanadi |
| `GET /stats` | dashboard uchun raqamlar (ixtiyoriy) |
| `GET /jobs/{id}` | uzoq davom etadigan amal holati. Amalni tizimning o'z Celery'si bajaradi |

**Xatolar** bir xil formatda qaytadi: `{"code": "not_found", "message": "...", "details": {}}`. Ishlatiladigan statuslar: 400, 401, 403, 404, 409, 422, 429, 5xx.

**SDK (`sdk/uzbmb-admin-sdk`)** bu repo ichidagi alohida Python paketi. Tizimlar uni o'rnatib, kontraktni bir xil tarzda bajaradi. Paketda quyidagilar bo'ladi:

- `verify_service_token(token, audience, jwks_url)`: tekshiruv yadrosi;
- Django DRF uchun `BFFServiceAuthentication` (authentication class) va `HasBFFScope("proctoring:sessions:read")` (permission class);
- FastAPI uchun `require_bff_scope("faceid:students:read")` dependency;
- har ikki framework uchun pagination va xato formati yordamchilari;
- yozish amallari uchun ixtiyoriy `jti` replay tekshiruvi (Redis'da TTL bilan);
- SDK'ning o'z testlari.

SDK `pip install` orqali ichki git manzilidan yoki lokal yo'ldan o'rnatiladi.

## 6. Autentifikatsiya: login, parol, TOTP, sessiya, CSRF

Kirish ikki qadamdan iborat. Birinchi qadam ikki usuldan biri bilan bajariladi: username va parol, yoki fuqaroning OneID'si. Ikkinchi qadam TOTP kod. **Egasining qarori (2026-11-23): TOTP hozircha o'chiq, production'da ham (`TOTP_REQUIRED=false`).** Kirish faqat birinchi qadam bilan bajariladi (pastda, "TOTP"). Sessiya Redis'da saqlanadi, brauzer esa faqat HttpOnly cookie oladi.

**Endpoint'lar:**

| Endpoint | Vazifasi |
| --- | --- |
| `POST /api/v1/auth/login` | username va parolni qabul qiladi. Javob: `{"mfa_required": true, "mfa_token": "..."}`. `mfa_token` bir martalik, 5 daqiqa amal qiladi, Redis'da saqlanadi. TOTP o'chiq bo'lsa, sessiya darhol ochiladi (`mfa_required: false`, cookie va `csrf_token`) |
| `POST /api/v1/auth/mfa` | `mfa_token` va TOTP kodni (yoki recovery code'ni) qabul qiladi. Sessiya cookie'sini o'rnatadi va body'da `csrf_token` qaytaradi |
| `POST /api/v1/auth/logout` | joriy sessiyani o'chiradi |
| `GET /api/v1/auth/sessions`, `DELETE /api/v1/auth/sessions/{id}` | adminning o'z faol sessiyalari ro'yxati va ularni tugatish |
| `POST /api/v1/auth/password` | parolni almashtiradi. Eski parol va TOTP kod talab qilinadi |
| `POST /api/v1/auth/totp/enroll`, `POST /api/v1/auth/totp/confirm` | TOTP'ni ulash. Birinchi kirishda majburiy |
| `POST /api/v1/auth/step-up` | TOTP kod qayta kiritiladi va sessiyadagi `mfa_at` yangilanadi |
| `GET /api/v1/auth/session` | joriy sessiya holati va `csrf_token`. Sahifa yangilanganda frontend tokenni shu yerdan qayta oladi |
| `GET /api/v1/auth/oneid/start`, `GET /api/v1/auth/oneid/callback` | OneID orqali kirish (pastda) |

**Parol:**

- Hash `argon2-cffi`'ning `PasswordHasher` klassi bilan (Argon2id) olinadi. Login vaqtida `check_needs_rehash` tekshiriladi.
- Parol kamida 12 belgidan iborat bo'lsin va username'ni o'z ichiga olmasin. Keng tarqalgan parollar ro'yxatiga qarshi tekshiriladi (ro'yxat lokal faylda). Davriy majburiy almashtirish talab qilinmaydi.
- **User enumeration'ga qarshi.** Foydalanuvchi topilmasa ham soxta hash tekshiruvi bajariladi, shunda javob vaqti farq qilmaydi. Har qanday xatoda bitta xabar qaytadi: "Login yoki parol noto'g'ri".

**Bloklash (Redis hisoblagichlari bilan):**

- Bitta username uchun 5 ta xato urinish, keyin 15 daqiqa blok.
- Bitta IP uchun 10 daqiqada 20 ta xato, keyin 30 daqiqa blok.
- Har bir blok audit'ga yoziladi va alert yuboriladi. Blokni superadmin oldinroq ochishi mumkin.

**TOTP:**

- **Hozircha o'chiq** (egasining qarori, 2026-11-23, production'da ham). `TOTP_REQUIRED=false` bo'lganda:
  - login'dan keyin darhol to'liq sessiya ochiladi;
  - birinchi kirishda TOTP ulash talab qilinmaydi, faqat parol almashtiriladi;
  - parol almashtirishda kod so'ralmaydi;
  - step-up so'ralmaydi.

  Kod va testlar saqlanadi. Yoqish uchun `TOTP_REQUIRED=true` qilinadi va servis qayta ishga tushiriladi. O'chiq paytida servis ishga tushishda `totp_disabled` ogohlantirishini yozadi, har bir login audit yozuvida `totp_required` bo'ladi. Pastdagi qoidalar TOTP yoqilganda amal qiladi.

- `pyotp`, 6 xonali kod, 30 soniyalik oyna, `valid_window=1`.
- Secret DB'da AES-GCM bilan shifrlab saqlanadi. Kalit (`TOTP_ENC_KEY`) servisga systemd credential sifatida beriladi (`LoadCredential=`, 11-bo'lim).
- **Kodni qayta ishlatib bo'lmaydi.** Oxirgi qabul qilingan `timecode` saqlanadi va undan kichik yoki teng kod rad etiladi.
- QR kod faqat ulash paytida bir marta ko'rsatiladi.
- Admin 10 ta recovery code oladi. Ular Argon2 bilan hash qilinadi va har biri bir martalik.

**Sessiya:**

- ID `secrets.token_urlsafe(32)` bilan yaratiladi. Redis kaliti `sess:<sha256(id)>` ko'rinishida bo'ladi, ID'ning o'zi saqlanmaydi.
- Sessiya ichida saqlanadi: `user_id`, `created_at`, `last_seen`, `mfa_at`, `ip`, `user_agent`, `csrf_token`, `perm_version`.
- Idle timeout 30 daqiqa (sliding TTL), absolute timeout 12 soat.
- Muvaffaqiyatli login'dan keyin har doim yangi ID beriladi (session fixation'ga qarshi).
- Cookie: `__Host-admin_session`, `HttpOnly; Secure; SameSite=Strict; Path=/`.
- **Sessiyalarni majburiy tugatish.** Parol o'zgarsa, admin bloklansa yoki uning roli o'zgarsa, uning barcha sessiyalari o'chiriladi. Buning uchun Redis'da `user_sessions:<user_id>` indeksi yuritiladi.

**CSRF:**

- Xavfsiz bo'lmagan metodlarda (POST, PUT, PATCH, DELETE) `X-CSRF-Token` sarlavhasi sessiyadagi token bilan `hmac.compare_digest` orqali solishtiriladi.
- Qo'shimcha ravishda `Origin` sarlavhasi ruxsat etilgan origin bilan solishtiriladi.

**Birinchi kirish va bootstrap:**

- Yangi admin yaratilganda `must_change_password=true` bo'ladi va TOTP ulanmagan holatda turadi. Bu holatda faqat `/auth/password` va `/auth/totp/*` endpoint'lari ishlaydi.
- Birinchi superadmin faqat `uv run python -m app.cli create-superadmin` buyrug'i bilan yaratiladi (parol interaktiv so'raladi). HTTP orqali yaratish imkoni yo'q.
- `AuthProvider` interfeysi: `authenticate()`, `verify_second_factor()`. Implementatsiyalari `LocalAuthProvider` (login + parol) va `OneIdAuthProvider`.

**OneID (fuqaroning yagona identifikatsiyasi):**

- Hozircha shablon. Kirish oqimi, sozlamalar va testlar tayyor, OneID bilan gaplashadigan HTTP client esa yozilmagan (`app/auth/oneid.py`, `TODO(owner)`). U OneID integratsiya hujjatlari olingandan keyin yoziladi. Shungacha `ONEID_ENABLED=false`. Client yozilmagan holda OneID yoqilsa, ilova ishga tushmaydi.
- OneID adminlikni bermaydi, u faqat odam kimligini tasdiqlaydi. Kirish faqat superadmin oldindan yaratgan, faol va PINFL'i biriktirilgan admin uchun ishlaydi. Avtomatik ro'yxatdan o'tish yo'q.
- PINFL ochiq holda saqlanmaydi: qidirish uchun uning HMAC-SHA256 hash'i (`PINFL_HMAC_KEY`), ko'rsatish uchun maskalangan ko'rinishi saqlanadi.
- OneID'dan keyin ham TOTP so'raladi.
- Har bir admin uchun ruxsat etilgan usullarni (`password`, `oneid`) superadmin belgilaydi (`admin_users.auth_methods`).
- `state` bir martalik va brauzerga cookie orqali bog'langan. `code`ni BFF server tomonida almashtiradi. `mfa_token` frontendga URL fragment'ida (`#mfa_token=`) beriladi.
- OneID yoqilganda BFF serveridan OneID serverlariga chiqish ochiladi (systemd `IPAddressAllow`, `TODO(owner)`).

## 7. Avtorizatsiya: RBAC, scope, step-up, deny-by-default

Har bir endpoint aniq bir permission talab qiladi. Permission'siz route topilsa, ilova ishga tushmaydi.

**Permission formati:** `system:resource:action`. Masalan: `faceid:students:read`, `proctoring:sessions:terminate`, `admin:users:write`, `audit:logs:read`.

- Wildcard faqat adminga berilgan permission'larda ishlatiladi: `faceid:*:read`, `faceid:*:*`, `*:*:*`. Endpoint talab qiladigan permission'da wildcard bo'lmaydi.
- **Registry.** Har bir connector permission'larini `permissions.py`'da e'lon qiladi. Yadroning o'z permission'lari ham bor: `admin:*`, `audit:*`. `sync-permissions` buyrug'i ularni DB bilan sinxronlaydi. Agar `require()` ichida e'lon qilinmagan permission ishlatilsa, startup xato beradi.

**Admin DB jadvallari:** `admin_users`, `roles`, `permissions`, `role_permissions`, `user_roles`, `user_scopes` (`scope_type`: region, zone yoki branch, va `scope_value`), `recovery_codes`, `audit_log`, `pending_actions`.

**Principal** joriy admin haqidagi ma'lumot: `user_id`, `username`, `permissions` (frozenset), `scopes`, `mfa_at`, `session_id`.

- Principal Redis'da keshlanadi. Rol o'zgarganda `perm_version` bittaga oshiriladi va keyingi so'rovda principal qayta yuklanadi. Bunga qo'shimcha ravishda 6-bo'limdagi sessiya o'chirish ham ishlaydi.
- Dependency'lar: `require("perm")`, `require_any(...)`, `require_recent_mfa(max_age=300)`, `require_authenticated` (masalan, `/me` uchun). FastAPI ularni bitta so'rov ichida keshlaydi.

**Deny-by-default:**

- Ishga tushishda barcha `APIRoute`'lar tekshiriladi. `require*` dependency'si yo'q va public ro'yxatda ham bo'lmagan route topilsa, `RuntimeError` ko'tariladi. Bu holat test bilan ham tekshiriladi.
- Public ro'yxat: `/api/v1/auth/login`, `/api/v1/auth/mfa`, `/api/v1/auth/oneid/start`, `/api/v1/auth/oneid/callback`, `/health`, `/ready`.

**Row-level tekshiruv (BOLA'ga qarshi):**

- Ro'yxat endpoint'larida adminning scope'i tizimga JWT'dagi `regions` claim'i orqali yuboriladi. BFF ham qaytgan natijani tekshiradi.
- Detail endpoint'larida ob'ekt admin scope'idan tashqarida bo'lsa, 404 qaytariladi. 403 emas, chunki ob'ekt mavjudligi oshkor bo'lmasligi kerak.
- Scope berilmagan admin hech narsani ko'rmaydi. Barcha hududlarga ruxsat faqat maxsus `*` scope aniq berilganda bo'ladi.

**Step-up MFA:**

- Qaysi amallar uchun: `ActionSpec.dangerous=True` deb belgilanganlar, o'chirish, bulk amallar, parol reset, PII eksport.
- Ular `require_recent_mfa(300)` bilan himoyalanadi. Shart bajarilmasa, 401 va `{"code": "step_up_required"}` qaytadi. Frontend shunda TOTP oynasini ochadi va kodni `/auth/step-up`'ga yuboradi.
- TOTP o'chiq bo'lsa (`TOTP_REQUIRED=false`, 6-bo'lim), step-up so'ralmaydi.

**4-ko'z prinsipi (2-navbat):**

- `ActionSpec.requires_approval=True` bo'lgan amal darhol bajarilmaydi, `pending_actions` jadvaliga yoziladi.
- Uni boshqa admin `admin:approvals:approve` permission'i bilan tasdiqlaydi. Admin o'z so'rovini o'zi tasdiqlay olmaydi.

**Rollar.** Seed qilinadigan yagona rol `superadmin`, u CLI orqali yaratiladi. Qolgan barcha rollarni superadmin adminkaning o'zida yaratadi: rol nomi, tavsifi va permission'lar ro'yxatidan tanlov.

- `GET /api/v1/admin/permissions` rol tahrirlash oynasi uchun ro'yxatni tizimlar bo'yicha guruhlab qaytaradi. Har bir permission'da o'zbekcha `description` bo'ladi, bu `PermissionSpec`'da majburiy maydon.
- Yangi tizim ulanib `sync-permissions` ishga tushirilganda, uning permission'lari bu ro'yxatda avtomatik paydo bo'ladi.
- Rolni o'chirib bo'lmaydi, agar u biror adminga biriktirilgan bo'lsa. Avval adminlardan olib tashlash kerak.

**Admin boshqaruvi:**

- Adminlar va rollar uchun CRUD hamda rol berish `admin:users:*`, `admin:roles:*` permission'lari bilan qilinadi.
- **Privilege escalation'ga qarshi:** admin boshqaga faqat o'zida bor permission'larni bera oladi va o'z rolini o'zgartira olmaydi.

## 8. Servislararo ishonch: service JWT, JWKS, kalit rotatsiyasi

BFF tizimga yuboradigan har bir so'rov uchun alohida JWT imzolaydi. Token 60 soniya amal qiladi va faqat o'sha so'rovga kerakli huquqni o'z ichiga oladi.

```json
{
  "iss": "admin-bff",
  "aud": "proctoring",
  "sub": "7d1c2f0e-uuid-of-admin",
  "name": "operator_toshkent",
  "scope": "proctoring:sessions:read",
  "regions": ["10", "11"],
  "iat": 1763640000,
  "nbf": 1763640000,
  "exp": 1763640060,
  "jti": "5b0c9a7e-...",
  "rid": "request-id"
}
```

- **Imzo.** Algoritm EdDSA (Ed25519). Private key faqat BFF'da saqlanadi va servisga systemd credential sifatida beriladi (`LoadCredential=`). Token sarlavhasida `kid` bo'ladi.
- **Eng kam huquq (least privilege).** `scope` ichida adminning barcha permission'lari emas, faqat shu chaqiruv uchun kerakli permission bo'ladi. `regions` adminning scope'ini bildiradi. Barcha hududlarga ruxsat bo'lsa, `["*"]` yoziladi.
- **JWKS.** Public kalitlar `GET /internal/jwks.json` orqali beriladi. Bu manzil faqat ichki tarmoqdan ochiladi, tashqi Nginx'da yopiq.
- **Rotatsiya.** `cli rotate-keys` buyrug'i yangi kalit yaratadi. Eski kalit JWKS'da yana 24 soat turadi. Rotatsiya har 90 kunda qilinadi va audit'ga yoziladi.
- **Yozish amallari.** Har bir amalga `Idempotency-Key` beriladi (frontenddan keladi, bo'lmasa BFF yaratadi). Tizim `jti` bo'yicha replay'ni rad etadi (SDK'da tayyor).
- **Tarmoq.**
  - Tizimlarning ichki API'si faqat `127.0.0.1`'da yoki unix socket'da tinglaydi. UFW tashqariga faqat 80, 443 va SSH'ni ochadi.
  - Hamma narsa bitta serverda bo'lgani uchun mTLS shart emas.
  - Tizimlar bir nechta serverga tarqalganda mTLS qo'shilishi kerak. `ConnectorClient` bunga tayyor bo'lsin: sertifikat yo'llari config'dan olinadi.

## 9. Audit log va shaxsiy ma'lumotlar himoyasi

Audit'ga har bir yozish amali, har bir login urinishi va shaxsiy ma'lumotni har bir ko'rish yoziladi. Yozilgan yozuvni hech kim o'zgartira olmaydi.

**`audit_log` jadvali** (oylik partition, `PARTITION BY RANGE (ts)`):

| Ustun | Tip | Izoh |
| --- | --- | --- |
| `id` | bigint identity |  |
| `ts` | timestamptz | UTC |
| `actor_id`, `actor_username` | uuid, text |  |
| `actor_ip`, `user_agent` | inet, text |  |
| `session_hash` | text | sessiya ID'ning sha256 hash'i |
| `action` | text | masalan, `proctoring.sessions.terminate` |
| `system_id`, `resource`, `resource_id` | text |  |
| `outcome` | text | `success`, `denied` yoki `error` |
| `status_code`, `request_id` | int, text |  |
| `before`, `after` | jsonb | PII maskalangan holda |
| `reason` | text | xavfli amallarda majburiy |
| `prev_hash`, `hash` | text | hash zanjiri |

**O'zgartirib bo'lmaslik:**

- **DB huquqlari.** Ilovaning DB user'i audit jadvalida faqat INSERT qila oladi. UPDATE, DELETE va TRUNCATE trigger orqali exception beradi.
- **Hash zanjiri.** Har bir yozuv hash'i oldingisiga bog'liq: `hash = sha256(prev_hash + canonical_json(row))`. Yozuvlar `pg_advisory_xact_lock` ostida ketma-ket yoziladi. `cli verify-audit` zanjir butunligini tekshiradi.
- **Nusxa.** Audit yozuvlari structlog orqali syslog yoki Loki'ga ham yuboriladi.

**Nima yoziladi:**

- login: muvaffaqiyatli, muvaffaqiyatsiz va bloklangan urinishlar;
- logout va step-up;
- har bir POST, PUT, PATCH va DELETE so'rovi;
- har bir 403 (rad etilgan) so'rov;
- PII'ni ochib ko'rish va eksport;
- admin va rollardagi o'zgarishlar;
- kalit rotatsiyasi.

Oddiy GET ro'yxatlar audit'ga yozilmaydi, ular faqat request log'ga tushadi.

**Audit API.** `GET /api/v1/audit` admin, tizim, amal, natija va sana bo'yicha filtrlarni qo'llab-quvvatlaydi va cursor pagination ishlatadi. Unga `audit:logs:read` permission'i kerak. CSV eksport uchun `audit:logs:export` va step-up talab qilinadi.

**Saqlash muddati: 90 kun.**

- Har kuni systemd timer orqali ishlaydigan vazifa to'liq 90 kundan eski bo'lgan oylik partition'larni o'chiradi.
- O'chirishdan oldin oxirgi o'chiriladigan yozuvning `hash`'i `audit_anchors` jadvaliga yoziladi. Shunda `verify-audit` qolgan zanjirni shu anchor'dan boshlab tekshira oladi.
- Partition o'chirilgani ham audit'ga yoziladi.

**Shaxsiy ma'lumotlar (PII):**

- `ResourceSpec`'da `pii=True` bilan belgilanadi: PINFL, pasport, telefon, yuz rasmi.
- **Ro'yxatlarda maskalanadi.** PINFL `3120*****0045`, telefon `+998 90 *** ** 45`, pasport `AB*****67` ko'rinishida chiqadi.
- **To'liq ko'rish.** Buning uchun `POST /api/v1/systems/{sys}/resources/{res}/{id}/reveal` chaqiriladi. U `<sys>:pii:reveal` permission'ini talab qiladi, sababi majburiy kiritiladi va har bir ko'rish audit'ga yoziladi.
- **Yuz rasmlari:**
  - BFF orqali stream qilinadi, buning uchun `<sys>:photos:view` permission'i kerak;
  - javobda `Cache-Control: no-store` bo'ladi, rasm Redis'da keshlanmaydi;
  - ochiq URL berilmaydi;
  - ro'yxatlarda rasm chiqmaydi.
- **Yuz embedding'lari** hech qachon frontendga chiqarilmaydi.
- **Loglarda PII bo'lmaydi.** structlog processor maskalaydi. Parol, TOTP kod, token va cookie log'ga umuman tushmaydi.
- **Saqlash joyi.** Ma'lumotlar O'zbekiston hududidagi serverlarda turadi. DB backup'lari shifrlanadi.

## 10. Frontend uchun API standarti

Frontend dasturchi faqat `/api/v1/openapi.json` sxemasi bilan ishlaydi. Shuning uchun barcha endpoint'lar bir xil formatda bo'ladi va `operationId`'lar o'zgarmaydi.

**OpenAPI:**

- **Versiya URL'da.** Prefiks `/api/v1`. Mavjud kontraktni buzadigan o'zgarish faqat `/api/v2`'da qilinadi.
- **Tavsif to'liq bo'ladi.** Har bir endpoint'da tizim bo'yicha `tags` bor. `operationId` `<system>_<resource>_<verb>` ko'rinishida yoziladi. Javob modellari Pydantic'da, misollar bilan.
- **Client generatsiya.** Frontend sxemadan `openapi-typescript` yoki `orval` bilan tiplangan client yasaydi.
- **CI tekshiruvi.** OpenAPI snapshot'i saqlanadi. Kontraktni buzadigan o'zgarish chiqsa, CI xato beradi.
- **`/docs` production'da yopiq.** U faqat `admin:api:docs` permission'i bor adminlarga ochiladi. Swagger assetlari lokal turadi.

**Pagination, filtr, saralash:**

- Oddiy pagination: `?page=1&page_size=50` (100 dan oshmaydi). Javob: `{"items": [], "page": 1, "page_size": 50, "total": 0}`.
- Katta jadvallar (masalan, audit) uchun cursor pagination: `?cursor=&limit=`. Javobda `next_cursor` qaytadi.
- Saralash `?sort=-created_at` ko'rinishida. Filtr va saralash maydonlari `ResourceSpec`'dagi ruxsat etilgan ro'yxatdan olinadi. Noma'lum parametr kelsa, 422 qaytadi.
- Vaqtlar ISO 8601 formatida, UTC'da (`Z` bilan). ID'lar string sifatida beriladi.

**Yagona xato formati:**

```json
{"error": {"code": "forbidden", "message": "Bu amal uchun ruxsat yo'q", "request_id": "...", "details": {}}}
```

Xato kodlari: `not_authenticated`, `session_expired`, `forbidden`, `step_up_required`, `csrf_failed`, `not_found`, `method_not_allowed` (405), `validation_error`, `conflict`, `rate_limited`, `system_unavailable`, `upstream_error`, `internal_error`. Tizim qaytargan xato matni frontendga o'zgarmasdan uzatilmaydi.

**Meta endpoint'lar.** Frontend menyu, jadval va formalarni shular asosida o'zi quradi:

- `GET /api/v1/me` qaytaradi:
  - admin ma'lumotlari, permission'lari va scope'lari;
  - `must_change_password` va TOTP holati.
- `GET /api/v1/meta/systems` adminning permission'iga qarab filtrlangan tizimlar ro'yxatini qaytaradi:
  - `id`, `display_name`, `health`;
  - `resources`: ustunlar, filtrlar, saralash, PII maydonlar;
  - `actions`: sarlavha, kirish ma'lumotlarining JSON Schema'si, `dangerous` va `requires_approval` belgilari.
- Standart sahifalar shu meta ma'lumotdan avtomatik yasaladi. Maxsus sahifalar (masalan, faceid kameralari yoki jonli monitoring) uchun connector'ning `extra_router` endpoint'lari ishlatiladi.

**Dashboard va holat:**

- `GET /api/v1/dashboard`:
  - tizimlarga parallel murojaat qiladi (`asyncio.gather`, har bir tizimga 3 soniya timeout);
  - qisman natija qaytaradi: `{"widgets": [...], "errors": [{"system": "proctoring", "code": "system_unavailable"}]}`;
  - natija Redis'da 30–60 soniya keshlanadi, kesh kaliti adminning scope'iga bog'liq.
- `GET /api/v1/systems/health`: tizimlar holati va circuit breaker holati.
- Uzoq davom etadigan amallar (bulk, eksport) `202 Accepted` va `job_id` qaytaradi. Holat `GET /api/v1/jobs/{id}` orqali olinadi. Amalni tizimning o'zi bajaradi.
- Real-time oqim va desktop clientlar endpoint'lari 10.1-bo'limda.

**Domen.** Adminka frontendi va API alohida domenlarda turadi, masalan `admin.uzbmb.uz` va `admin-api.uzbmb.uz` (aniq nomlar keyin beriladi). Ikkalasi bitta asosiy domen ostida bo'lishi shart. Shunda ular same-site hisoblanadi va `SameSite=Strict` cookie ishlaydi.

- CORS faqat frontend origin'i uchun `allow_credentials=True` bilan ochiladi. `*` hech qachon ishlatilmaydi.
- Frontend barcha so'rovlarni `credentials: 'include'` bilan yuboradi. SSE uchun `new EventSource(url, { withCredentials: true })` ishlatiladi.
- CSRF tekshiruvida `Origin` aynan shu frontend origin'i bilan solishtiriladi.
- `__Host-` prefiksli cookie API domenida qoladi va `Domain` atributisiz o'rnatiladi.
- Ikkala domenga kirish faqat bino ichki tarmog'idan, Nginx IP allowlist orqali (11-bo'lim).

## 10.1. Desktop clientlar boshqaruvi va real-time monitoring

Adminkadan desktop clientlarning (SafeBrowser, proctoring client, Face-ID desktop) versiyalari, majburiy yangilanishi va sozlamalari boshqariladi. Imtihon jarayoni va turniketlar real vaqtda kuzatiladi.

### Desktop clientlar

- **Egalik.** Har bir client o'z backend tizimiga tegishli: SafeBrowser va proctoring client `proctoring`'ga, Face-ID desktop `faceid`'ga. Ma'lumot o'sha tizimda saqlanadi, BFF faqat boshqaradi.
- **Kontrakt.** Clientlari bor har bir tizim ichki admin API'ga quyidagi standart endpoint'larni qo'shadi (SDK'da modellar tayyor bo'ladi):

| Ichki endpoint | Vazifasi |
| --- | --- |
| `GET /client-releases` | versiyalar ro'yxati: `version`, `channel` (stable yoki beta), `file_url`, `sha256`, `signature`, `released_at`, `notes` |
| `POST /actions/publish-release` | yangi versiyani e'lon qilish |
| `POST /actions/set-min-version` | eng past ruxsat etilgan versiyani belgilash. Undan eski clientlar majburiy yangilanadi |
| `GET /client-config`, `POST /actions/update-client-config`, `POST /actions/rollback-client-config` | sozlamalar (JSON), global va hudud yoki guruh darajasida. Har bir o'zgarish yangi versiya bo'ladi va oldingisiga qaytarish mumkin |
| `GET /client-instances` | ishlab turgan clientlar: kompyuter raqami, MAC, versiya, oxirgi heartbeat, holat |

- **Client tomoni.** Clientlar `min_version` va config'ni o'z backend'idan oladi. Buning uchun mavjud health/heartbeat so'rovi kengaytiriladi.
- **Xavfsizlik:**
  - Installer fayllar kod imzosi bilan imzolanadi. Client faylni yuklab olgach `sha256` va imzoni tekshiradi, mos kelmasa o'rnatmaydi.
  - `publish-release`, `set-min-version` va config o'zgarishi bir vaqtda minglab kompyuterga ta'sir qiladi. Shuning uchun ular `dangerous=True` (step-up) va `requires_approval=True` (ikkinchi admin tasdig'i) deb belgilanadi.
  - Har bir o'zgarish `before`/`after` bilan audit'ga yoziladi.
  - Tavsiya (egasi tasdiqlasin): aktiv imtihon sessiyasi bor kompyuterlarda majburiy yangilanish smena tugaguncha kechiktiriladi.
- **BFF'dagi umumiy sahifa.** `GET /api/v1/clients` barcha tizimlar bo'yicha qaysi versiya nechta kompyuterda ishlayotganini va eskirgan clientlarni ko'rsatadi.
- **Permission'lar:** `<sys>:clients:read`, `<sys>:clients:release`, `<sys>:clients:config`.

### Real-time monitoring

Voqealar zanjiri: tizim → Redis Stream → BFF → SSE → brauzer.

- **Alohida Redis instansi.** Voqealar uchun sessiya Redis'idan alohida instans ishlatiladi (`127.0.0.1` yoki unix socket). Tizimlar BFF sessiyalariga hech qanday yo'l bilan yeta olmasligi kerak.
- **Redis ACL:**
  - Har bir tizimning o'z user'i bor va u faqat o'z kalitiga yoza oladi. Misol: `ACL SETUSER proctoring on >*** ~events:proctoring +xadd`.
  - BFF user'i faqat o'qiydi (`+xread +xreadgroup +xack`).
  - Stream uzunligi cheklanadi: `XADD ... MAXLEN ~ 100000`.
- **Voqea formati.** Unda PII minimal bo'ladi: rasm yo'q, PINFL maskalangan.

```json
{"id": "...", "system_id": "proctoring", "type": "violation.detected", "ts": "2026-11-20T09:15:02Z", "region_id": "10", "severity": "warning", "data": {"computer_no": "A-117", "kind": "second_monitor"}}
```

- **BFF endpoint'i** `GET /api/v1/events/stream?systems=proctoring,ejournal&types=...` (`text/event-stream`):
  - **Kirish.** Sessiya cookie'si orqali, har bir tizim uchun `<sys>:events:read` permission'i talab qilinadi.
  - **Filtr.** Har bir voqea adminning scope'i (`region_id`) bo'yicha filtrlanadi.
  - **Qayta ulanish.** `Last-Event-ID` bilan qayta ulanganda o'tkazib yuborilgan voqealar stream'dan beriladi.
  - **Heartbeat va yopilish.** Har 15 soniyada `: ping` yuboriladi. Sessiya tugasa yoki adminning roli o'zgarsa, oqim yopiladi.
  - **Cheklov.** Bitta sessiyada ko'pi bilan 3 ta ochiq oqim bo'ladi.
- **Yuqori oqimli voqealar.** Masalan, turniketdan o'tishlar brauzerga xom holda yuborilmaydi. Ular har 2 soniyada agregat hisoblagich sifatida (`turnstile.stats`) jo'natiladi. Xom holda faqat `severity` `warning` va undan yuqori bo'lgan voqealar yuboriladi.
- **Tizim tomoni.** SDK'da `publish_event(type, region_id, severity, data)` yordamchisi bo'ladi. U Django signal yoki Celery task ichidan chaqiriladi. Ejournal'dagi mavjud Channels oqimi o'zgarmaydi, voqealar qo'shimcha ravishda stream'ga ham yoziladi.
- **Bildirishnomalar.** `severity=critical` voqealar va tizim ishlamay qolgan holatlar adminkaning o'zida shu oqim orqali bildirishnoma bo'lib chiqadi. Telegram yoki email hozircha yo'q.
- **Nginx.** SSE location uchun `proxy_buffering off; proxy_read_timeout 1h;` sozlanadi.

## 11. Barqarorlik, kuzatuv va deploy

Bitta tizim ishlamay qolsa ham adminka ishlashda davom etadi. Tashqariga faqat Nginx ochiq bo'ladi.

**Barqarorlik:**

- **Har bir tizim uchun bitta `httpx.AsyncClient`.** U lifespan'da yaratiladi. Parametrlar: `Timeout(5, connect=2)`, `max_connections=50`.
- **Retry.** Faqat GET va boshqa idempotent so'rovlar qayta yuboriladi, ko'pi bilan 2 marta. Qayta yuborish faqat ulanish xatosi, 502, 503 yoki 504 bo'lganda qilinadi, exponential backoff va jitter bilan.
- **Circuit breaker** (har bir tizim uchun alohida):
  - ketma-ket 5 ta xatodan keyin 30 soniyaga ochiladi, keyin half-open holatiga o'tadi;
  - o'zimiz yozamiz (taxminan 60 qator kod), alohida kutubxona kerak emas;
  - holati `/systems/health`'da ko'rinadi.
- **Rate limit** (Redis'da):
  - login uchun 6-bo'limdagi qoidalar;
  - har bir sessiyaga umumiy 300 so'rov/daqiqa;
  - eksport uchun 5 marta/soat.
- **Request body** 1 MB'dan oshmaydi.

**Kuzatuv:**

- **Loglar.** structlog JSON formatida journald'ga yozadi: `ts`, `level`, `request_id`, `user_id`, `system_id`, `path`, `status`, `duration_ms`. PII'ni maskalaydigan processor bor. `/health` so'rovlari log'ga yozilmaydi.
- **`X-Request-ID`.** So'rov bilan kelsa, UUID ekanligi tekshiriladi. Kelmasa, yangisi yaratiladi. U tizimlarga uzatiladi va javobda ham qaytariladi.
- **Metrikalar.** Prometheus `/metrics` endpoint'i faqat ichki tarmoqdan ochiladi. Unda quyidagilar bo'ladi:
  - HTTP so'rovlar;
  - har bir tizim bo'yicha kechikish va xatolar;
  - circuit breaker holati;
  - muvaffaqiyatsiz login'lar va bloklanishlar soni.
- **Alertlar (2-navbat).** Tashqi kanal (Telegram, email) hozircha yo'q. Kerak bo'lganda alertlar adminkaning o'zida bildirishnoma sifatida chiqadi (10.1-bo'lim). Alert beriladigan holatlar:
  - bloklanishlar soni keskin oshdi;
  - 5xx xatolar 1% dan oshdi;
  - biror tizim 2 daqiqadan ortiq ishlamayapti;
  - bitta admin bir daqiqada g'ayrioddiy ko'p yozish amali bajardi.
- **Holat endpoint'lari.** `/health` (liveness) va `/ready` (DB va Redis ishlayaptimi).

**Deploy:**

- **Docker ishlatilmaydi.** BFF systemd servisi sifatida ishlaydi.
- **Joylashuv:**
  - kod `/opt/admin-bff`'da turadi;
  - virtualenv `uv sync --frozen --no-dev` bilan yaratiladi;
  - config `/etc/admin-bff/`'da, loglar journald'da.
- **Alohida tizim user'i.** Servis login shell'siz `admin-bff` user'i nomidan ishlaydi. U hech qachon root bo'lib ishga tushmaydi.
- **`deploy/admin-bff.service`:**
  - Gunicorn + UvicornWorker faqat unix socket'da tinglaydi: `/run/admin-bff/bff.sock` (`RuntimeDirectory=admin-bff`);
  - Nginx socket'ga guruh orqali kiradi;
  - `ExecReload` HUP signali bilan sessiyalarni uzmasdan qayta yuklaydi.
- **systemd hardening:**
  - `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`;
  - `ReadWritePaths` faqat kerakli papkalar uchun, `CapabilityBoundingSet` bo'sh;
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryMax`, `Restart=on-failure`;
  - `systemd-analyze security admin-bff` iloji boricha past ball ko'rsatishi kerak.
- **Secrets:**
  - `TOTP_ENC_KEY`, JWT private key, DB va Redis parollari `LoadCredential=` orqali beriladi;
  - ilova ularni `$CREDENTIALS_DIRECTORY`'dan o'qiydi (pydantic-settings `secrets_dir`);
  - manba fayllar `/etc/admin-bff/credentials/`'da, `root:root 0600` huquqi bilan saqlanadi;
  - `.env` faqat development uchun, repo'da faqat `.env.example` turadi.
- **PostgreSQL va Redis host'ning o'zida:**
  - ular faqat `127.0.0.1` yoki unix socket'da tinglaydi;
  - PostgreSQL `scram-sha-256` bilan, BFF uchun alohida DB va user;
  - sessiya Redis'ida `requirepass`, voqealar Redis'ida ACL (10.1-bo'lim, `deploy/redis-events.conf`).
- **UFW.** Tashqariga faqat 80, 443 va SSH ochiq, SSH faqat ma'lum IP'lardan. Tizimlarning ichki API portlari tashqariga ochilmaydi.
- **Nginx** (frontend va API uchun alohida server bloklari):
  - TLS 1.2/1.3, HSTS, `client_max_body_size 1m`;
  - `/api/v1/auth/` uchun rate limit;
  - IP allowlist: faqat bino ichki tarmog'i diapazonlari (`allow <diapazon>; deny all;`, diapazonlarni egasi beradi);
  - security header'lar: `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`;
  - `/internal/` va `/metrics` tashqaridan yopiq;
  - SSE location (10.1-bo'lim);
  - ModSecurity + OWASP CRS, avval `DetectionOnly` rejimida.
- **`deploy/deploy.sh`.** Ketma-ketlik: `git pull`, `uv sync --frozen`, `alembic upgrade head`, `systemctl reload admin-bff`. CI `alembic heads` bitta ekanini tekshiradi.
- **Backup.** PostgreSQL har kuni `pg_dump` qilinadi (systemd timer), shifrlanadi va boshqa serverga ko'chiriladi. Tiklash har oy sinab ko'riladi.

## 12. Testlar, ish bosqichlari va Definition of Done

Ish 10 ta bosqichda bajariladi. Har bir bosqich testlari va CI yashil bo'lgandan keyingina tugagan hisoblanadi.

**Test muhiti:**

- pytest + pytest-asyncio ishlatiladi.
- Lokal o'rnatilgan PostgreSQL va Redis'da alohida test DB yaratiladi. Fixture'lar uni har test sessiyasida yaratib, oxirida tozalaydi. Tizimlar respx bilan mock qilinadi.

**Majburiy testlar:**

- **Auth:**
  - to'g'ri login va TOTP;
  - noto'g'ri parol va mavjud bo'lmagan user uchun bir xil xabar;
  - 5 ta xatodan keyin bloklash;
  - TOTP kodni qayta ishlatib bo'lmaydi, recovery code bir martalik;
  - login'dan keyin sessiya ID o'zgaradi;
  - idle va absolute timeout ishlaydi;
  - parol o'zgarganda barcha sessiyalar o'chadi.
- **CSRF:** `X-CSRF-Token` sarlavhasiz POST va noto'g'ri `Origin` 403 qaytaradi.
- **RBAC:**
  - permission bo'lmasa 403 qaytadi;
  - wildcard to'g'ri ishlaydi;
  - himoyasiz route bo'lsa ilova ishga tushmaydi;
  - admin o'z huquqini oshira olmaydi;
  - rol o'zgarishi keyingi so'rovdayoq kuchga kiradi;
  - superadmin yaratgan rol permission'lari to'g'ri qo'llanadi.
- **BOLA:** boshqa hudud ob'ektini so'raganda 404 qaytadi.
- **Step-up:** `mfa_at` eski bo'lsa, `step_up_required` qaytadi.
- **Service JWT va SDK:**
  - `aud`, `exp` va `scope` to'g'ri qo'yiladi;
  - SDK boshqa `aud`'li va muddati o'tgan tokenni rad etadi.
- **Audit:**
  - har bir yozish amali yoziladi;
  - UPDATE va DELETE trigger tufayli xato beradi;
  - `verify-audit` buzilgan zanjirni topadi;
  - 90 kunlik retention'dan keyin anchor orqali zanjir tekshiriladi.
- **Connector:**
  - timeout va circuit breaker ishlaydi;
  - dashboard qisman natija qaytaradi;
  - tizim xatosi yagona formatga keltiriladi.
- **PII:**
  - ro'yxatlarda maskalangan;
  - reveal audit'ga yoziladi;
  - log'larda PII yo'q (test log chiqishini tekshiradi).
- **Real-time:**
  - SSE oqimi admin scope'idan tashqaridagi voqeani yubormaydi;
  - permission'siz tizim oqimi 403 qaytaradi;
  - `Last-Event-ID` bilan o'tkazib yuborilgan voqealar qayta beriladi;
  - sessiya tugaganda oqim yopiladi.
- **Desktop clientlar:**
  - `publish-release` step-up va ikkinchi admin tasdig'isiz bajarilmaydi;
  - config rollback ishlaydi.

**Coverage:** `auth`, `rbac`, `audit` va `service_auth` modullarida kamida 90%, umumiy kamida 80%.

**CI tekshiruvlari:** ruff, mypy, pytest, pip-audit, bandit, Alembic'da bitta head, OpenAPI farqi.

| Bosqich | Natija | Qabul mezoni |
| --- | --- | --- |
| 0. Skelet | pyproject, papkalar tuzilishi, settings, logging, xato formati, `/health`, `deploy/` (systemd unit, Nginx config namunalari), CI | lokal ishga tushadi, `/health` 200 qaytaradi, CI yashil |
| 1. Auth | adminlar jadvali, Argon2, TOTP, sessiya, CSRF, bloklash, `create-superadmin` | 6-bo'limning testlari o'tadi |
| 2. RBAC | permission registry, rollarni adminkada yaratish, scope'lar, `require()`, deny-by-default, adminlar/rollar/permission'lar API, `/me` | 7-bo'limning testlari o'tadi |
| 3. Audit | jadval, trigger, hash zanjiri, 90 kunlik retention, audit API | 9-bo'limning testlari o'tadi |
| 4. Service auth va SDK | JWT signer, JWKS, rotatsiya, `sdk/` (DRF + FastAPI) | SDK testlari o'tadi |
| 5. Connector framework | `base`, `registry`, `generic`, meta endpoint'lar, `_template`, mock tizim | mock tizim bilan e2e test o'tadi |
| 6. Birinchi connector: Face-ID | Face-ID (FastAPI) tizimida ichki admin API, `faceid` connector'i, hozirgi Face-ID adminkasidagi funksiyalar | staging'da haqiqiy Face-ID tizimiga ulangan |
| 7. Qolgan connector'lar | proctoring, ejournal, quloq | har biri uchun contract test |
| 8. Dashboard, real-time va desktop clientlar | dashboard, `/systems/health`, `/jobs`, SSE oqimi, voqealar Redis'i va ACL, client releases va config | 10- va 10.1-bo'limlarning testlari o'tadi |
| 9. Hardening va deploy | systemd hardening, Nginx, WAF, IP allowlist, backup, metrikalar | OWASP ASVS Level 2 checklist bo'yicha hisobot |

**Definition of Done:**

- Barcha testlar va CI yashil.
- OpenAPI to'liq va misollar bilan yozilgan.
- `docs/` papkasida uchta hujjat bor:
  - `docs/frontend.md`: auth jarayoni, CSRF, step-up, xato kodlari, meta endpoint'lar;
  - `docs/adding-a-system.md`: yangi tizim qo'shish tartibi;
  - `docs/security.md`: qisqa threat model va qabul qilingan qarorlar.
- O'zbek tilidagi README'da ishga tushirish, deploy va CLI buyruqlari yozilgan.
- Har bir bosqich bo'yicha hisobot berilgan (1-bo'limdagi format bo'yicha).

## 13. Siz to'ldirishingiz kerak bo'lgan ma'lumotlar

Bu savollarga javobni agentga ishni boshlashdan oldin bering. Javobi yo'q savollar 6-bosqichgacha `TODO` bo'lib turadi.

- [x] Har bir tizim uchun: base URL yoki unix socket, hozirgi adminkada qilinadigan ishlar, adminkada qaysi ro'yxatlar va amallar kerakligi.

  Javob: har bir tizimning hozirgi adminkasidagi funksiyalar aynan ko'chiriladi. Face-ID manzili 2-bo'limdagi misolda yozilgan, qolgan tizimlarniki keyin beriladi.
- [x] Hududiy cheklov modeli: adminlar qaysi daraja bo'yicha cheklanadi (viloyat, zona, bino, smena).

  Javob: barcha adminlar bitta markaziy binoda, lokal tarmoqda ishlaydi. Kompyuter `hosts` fayliga yozilgan bo'lsa, adminka ochiladi. Hududiy cheklash hozircha kerak emas. Scope mexanizmi (7-bo'lim) baribir quriladi va adminlarga `*` (barcha hududlar) beriladi. Kerak bo'lganda superadmin adminkaning o'zida cheklaydi, kod o'zgarmaydi.
- [x] Rollar: qanday lavozimlar bor (masalan, viloyat operatori, markaz admini, auditor) va har biri nima qila oladi.

  Javob: rollarni superadmin adminkaning o'zida yaratadi (7-bo'lim).
- [ ] Xavfli amallar ro'yxati: qaysilari uchun step-up, qaysilari uchun ikkinchi admin tasdig'i kerak.

  Javob hali yo'q. Hozircha 7- va 10.1-bo'limlardagi sukut bo'yicha ro'yxat ishlatiladi.
- [x] Domen: adminka va API qaysi domenda bo'ladi. Kirish IP allowlist orqalimi yoki VPN orqali.

  Javob: adminka va API alohida domenlarda bo'ladi, kirish IP allowlist orqali (10- va 11-bo'limlar).
- [x] Audit log saqlash muddati.

  Javob: 90 kun (9-bo'lim).
- [x] Alertlar qayerga yuboriladi (Telegram guruh, email).

  Javob: hozircha shart emas. Kerak bo'lsa, adminkaning o'zida chiqadi (11-bo'lim).
- [x] Birinchi qaysi tizim ulanadi.

  Javob: Face-ID tizimi, FastAPI backend (12-bo'lim, 6-bosqich).
- [x] SafeBrowser va desktop clientlarni adminkadan boshqarish kerakmi (versiyalar, majburiy yangilanish, sozlamalar).

  Javob: ha (10.1-bo'lim).
- [x] Adminkada real-time monitoring kerakmi (turniketlar, imtihon jarayoni).

  Javob: ha (10.1-bo'lim).
- [x] BFF qaysi serverda ishlaydi va qanday ishga tushiriladi (Docker yoki systemd).

  Javob: systemd orqali, Docker ishlatilmaydi (11-bo'lim). Qaysi serverda ishlashi keyin aniqlanadi.
