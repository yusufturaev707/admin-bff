# Loyiha xaritasi (oddiy tilda)

Bu hujjat loyiha egasi uchun yozilgan. Unda kod qanday tuzilgani, so'rov
qanday yo'l bosishi va yangi narsa qo'shish uchun qaysi fayllarni ochish
kerakligi tushuntiriladi.

Hammasini birdan o'qish shart emas:

* **Avval** 1, 2 va 3-bo'limlarni o'qing (umumiy rasm).
* **Yangi narsa qo'shishda** 5-bo'limdan tegishli "retsept"ni oching.
* **Notanish so'z uchrasa**, 4-bo'limga (lug'at) qarang.
* **Ilova** (oxirida) har bir faylni bir qatorda tavsiflaydi. Uni o'qimaysiz,
  kerak bo'lganda qidirasiz.

## 1. Umumiy rasm

BFF (Backend for Frontend) adminka frontendi va boshqa tizimlar o'rtasida
turadi. Frontend faqat BFF bilan gaplashadi, BFF esa o'z bazasi va Redis
bilan ishlaydi. Keyinroq u Face-ID, proctoring va boshqa tizimlarga ham
ularning API'si orqali ulanadi (bu qism hali yozilmagan).

```
Brauzer (adminka yoki Swagger)
   |  HTTPS
   v
Tashkilot proxy'si (kpi.uzbmb.uz; TLS shu yerda tugaydi)
   |  HTTP, 8080-port
   v
Nginx, BFF serverida (deploy/nginx/admin-api.conf)
   |  IP allowlist, xavfsizlik sarlavhalari, login uchun rate limit
   |  unix socket: /run/admin-bff/bff.sock
   v
Gunicorn -> FastAPI ilova (app/)
   |-- PostgreSQL, boshqa serverda: adminlar, rollar, hududlar, audit log
   '-- Redis, shu serverda (admin-bff-redis): sessiyalar, login bloklari, kesh
```

Hajmi (taxminan): `app/`da 7 800 qator kod, `tests/`da 5 600 qator test.

## 2. Bitta so'rovning yo'li

Misol: frontend yangi hudud qo'shadi.

```
POST /api/v1/admin/regions
Cookie: __Host-admin_session=...
X-CSRF-Token: ...
{"name": "Jizzax viloyati"}
```

So'rov quyidagi bosqichlardan o'tadi. Biror bosqichda xato chiqsa, so'rov
shu yerda to'xtaydi va frontend xato oladi.

| # | Nima bo'ladi | Fayl | Xato bo'lsa |
| --- | --- | --- | --- |
| 1 | Nginx so'rovni qabul qiladi, IP'ni tekshiradi, socket'ga uzatadi | `deploy/nginx/admin-api.conf` | 403 |
| 2 | So'rovga ID beriladi, log qatori yoziladi | `app/core/request_id.py` | |
| 3 | Audit so'rovni kuzatib turadi: har bir POST, PATCH, DELETE va 403 yoziladi | `app/audit/middleware.py` | |
| 4 | Body 1 MB'dan katta emasligi tekshiriladi | `app/core/body_limit.py` | 413 |
| 5 | `Origin` sarlavhasi tekshiriladi (so'rov bizning frontenddan kelganmi) | `app/auth/csrf.py` | 403 `csrf_failed` |
| 6 | FastAPI endpoint funksiyasini topadi: `create_region` | `app/api/v1/directory.py` | 404 / 405 |
| 7 | Cookie'dan sessiya Redis'dan o'qiladi | `app/auth/dependencies.py` (`current_session`) | 401 |
| 8 | `X-CSRF-Token` sessiyadagi token bilan solishtiriladi | o'sha fayl | 403 `csrf_failed` |
| 9 | Admin kimligi va ruxsatlari yuklanadi (Redis'da keshlanadi) | `app/rbac/principal.py` | |
| 10 | `admin:regions:write` ruxsati bormi? Yo'q bo'lsa, rad etish audit'ga yoziladi | `app/rbac/dependencies.py` (`require`) | 403 `forbidden` |
| 11 | Body tekshiriladi: `name` bormi, uzunligi to'g'rimi, ortiqcha maydon yo'qmi | `app/directory/schemas.py` (`RegionCreate`) | 422 |
| 12 | Hudud bazaga yoziladi. Shu nom allaqachon bo'lsa, rad etiladi | `app/directory/service.py` (`create_region`) | 409 `conflict` |
| 13 | Audit yozuvi qo'shiladi: kim, qachon, qanday qiymat bilan | `app/audit/writer.py` | |
| 14 | Javob `RegionOut` ko'rinishida JSON bo'lib qaytadi | `app/directory/schemas.py` | |

2-5-qadamlar **middleware**: ular har bir so'rovda avtomatik ishlaydi va
`app/main.py`da ulanadi. 7-11-qadamlar endpoint funksiyasining parametrlarida
yoziladi va FastAPI ularni funksiyadan oldin bajaradi:

* `actor: RegionsWrite` **dependency**. U "7-10-qadamlarni bajar" degani.
* `body: RegionCreate` **schema**. U 11-qadamdagi tekshiruvni beradi.

Xato qaysi qadamda chiqmasin, frontend bir xil formatdagi javob oladi:

```json
{"error": {"code": "forbidden", "message": "Bu amal uchun ruxsat yo'q", "request_id": "...", "details": {}}}
```

Buni `app/core/errors.py` qiladi. Kodda xato `raise AppError(ErrorCode.FORBIDDEN)`
ko'rinishida chiqariladi.

**Eng muhim xulosa:** endpoint funksiyasi qisqa, xavfsizlik tekshiruvlari esa
avtomatik ishlaydi. Yangi endpoint yozganda faqat kerakli ruxsatni
(`require("...")`) ko'rsatasiz. Ruxsat ko'rsatilmagan endpoint bo'lsa, ilova
umuman ishga tushmaydi (`app/rbac/route_check.py`). Shu tarzda himoyasiz
endpoint tasodifan production'ga chiqib ketmaydi.

## 3. Papkalar: qaysi qism kimniki

### Siz tegadigan qism

| Joy | Nima bor |
| --- | --- |
| `app/api/v1/` | Endpoint'lar (URL'lar). Har bir fayl bitta mavzu: `auth.py` (kirish), `me.py` (joriy admin), `admin.py` (adminlar va rollar), `directory.py` (hududlar va tashkilotlar), `audit.py` (audit log) |
| `app/directory/` | Hududlar va tashkilotlar: `models.py` (jadval), `schemas.py` (API maydonlari), `service.py` (mantiq). **Yangi funksiya uchun namuna shu** |
| `app/rbac/permissions.py` | Barcha ruxsatlar ro'yxati (`CORE_PERMISSIONS`) va ularning o'zbekcha tavsifi |
| `migrations/versions/` | Bazadagi o'zgarishlar tarixi. Har bir fayl bitta qadam: `0001` ... `0006` |
| `tests/` | Testlar. Tuzilishi `app/` bilan bir xil: `tests/directory/` `app/directory/`ni tekshiradi |

### Ba'zan kerak bo'ladigan qism

| Joy | Nima bor |
| --- | --- |
| `app/main.py` | Ilovani yig'adi. Yangi router va yangi service shu yerga ulanadi |
| `app/settings.py` | Barcha sozlamalar. Ular `.env`dan (lokal) yoki `/etc/admin-bff/`dan (server) o'qiladi |
| `app/rbac/service.py` | Adminlar va rollar: yaratish, tahrirlash, rol berish. "Admin o'zida yo'q ruxsatni boshqaga bera olmaydi" qoidasi ham shu yerda |
| `app/auth/models.py` | `users` jadvali (foydalanuvchilar) |
| `deploy/` | Server fayllari: systemd servisi, nginx, `admin-bff` buyrug'i (`admin-bff.sh`) |
| `scripts/create_superadmin.py` | Birinchi superadmin'ni yaratish |

### O'zi ishlaydigan qism (tushunish shart emas)

| Joy | Nima bor |
| --- | --- |
| `app/auth/` | Login, parol hash'i (Argon2), sessiya (Redis), CSRF, xato urinishlarda bloklash, OneID shabloni |
| `app/audit/` | Audit log: yozish, hash zanjiri, ko'rish, CSV eksport |
| `app/core/` | Bazaga ulanish, loglar, xato formati, sahifalash (pagination), request ID, metrikalar |
| `app/api/docs.py` | Swagger sahifasi (`/api/v1/docs`) va OpenAPI sxemasi |

Bu qismni testlar qo'riqlaydi. `uv run pytest` o'tsa, u ishlayapti.

### Nega bunchalik ko'p himoya?

Har bir himoya aniq bir xavfga qarshi qo'yilgan. Ularning hammasini CLAUDE.md
talab qiladi:

| Himoya | Nimadan saqlaydi | Qayerda |
| --- | --- | --- |
| Sessiya faqat HttpOnly cookie'da | Sahifaga zararli skript tushsa ham, u sessiyani o'g'irlay olmaydi | `app/auth/sessions.py` |
| CSRF token va `Origin` tekshiruvi | Boshqa sayt adminning brauzeri nomidan so'rov yubora olmaydi | `app/auth/csrf.py`, `app/auth/dependencies.py` |
| 5 ta xato urinishdan keyin blok | Parolni tanlab topishga urinish (brute force) | `app/auth/lockout.py` |
| Argon2 parol hash'i | Baza o'g'irlansa ham, parollarni ochish juda qimmatga tushadi | `app/auth/passwords.py` |
| Har bir endpoint'da ruxsat (deny-by-default) | Unutilgan, himoyasiz endpoint | `app/rbac/route_check.py` |
| Audit log va hash zanjiri | Kim nima qilganini yashirish yoki yozuvni o'zgartirish | `app/audit/` |
| PINFL faqat hash va maska ko'rinishida | Baza o'g'irlansa ham, fuqarolarning PINFL'i ochilmaydi | `app/rbac/service.py` (`_imie`), `app/core/pii.py` |
| Nginx IP allowlist | Bino tarmog'idan tashqaridan kirish | `deploy/nginx/admin-allowlist.conf` |

## 4. Lug'at

| So'z | Ma'nosi |
| --- | --- |
| **Endpoint** | Bitta URL va metod, masalan `POST /api/v1/admin/regions` |
| **Router** | Endpoint'lar guruhi (bitta fayl). `app/main.py`da `include_router` bilan ulanadi |
| **Model** | Bazadagi jadvalning Python'dagi tavsifi (SQLAlchemy). Masalan `class Region` |
| **Schema** | API qabul qiladigan va qaytaradigan JSON'ning tavsifi (Pydantic). Masalan `RegionCreate`, `RegionOut` |
| **Service** | Mantiq turadigan klass: tekshiruvlar, bazaga yozish, audit. Endpoint uni chaqiradi |
| **Migratsiya** | Bazani o'zgartiradigan fayl (Alembic): jadval yoki ustun qo'shish. `upgrade` oldinga, `downgrade` orqaga |
| **Middleware** | Har bir so'rovdan oldin va keyin ishlaydigan kod (2-bo'lim, 2-5-qadamlar) |
| **Dependency** | Endpoint parametrida yoziladigan tekshiruv yoki qiymat (`Depends(...)`). FastAPI uni endpoint'dan oldin bajaradi |
| **Sessiya** | Login qilgan adminning Redis'dagi yozuvi. Brauzerda uning faqat ID'si (cookie) turadi |
| **CSRF** | Boshqa saytdan yashirin so'rov yuborish hujumi. `X-CSRF-Token` shunga qarshi |
| **Permission (ruxsat)** | `tizim:resurs:amal` ko'rinishidagi huquq, masalan `admin:regions:write` |
| **Rol** | Ruxsatlar to'plami. Adminga rol beriladi. `superadmin` rolida `*:*:*`, ya'ni hamma ruxsat bor |
| **Principal** | Joriy so'rovni yuborgan admin: ID, login va ruxsatlari |
| **Audit** | "Kim, qachon, nima qildi" jurnali. Yozuvni o'zgartirib ham, o'chirib ham bo'lmaydi |
| **operationId** | Endpoint'ning o'zgarmas nomi, masalan `admin_regions_create`. Frontend client'i shu nom bilan yasaladi |
| **OpenAPI / Swagger** | API'ning to'liq tavsifi (`openapi.json`) va uni ko'rsatadigan sahifa (`/api/v1/docs`) |
| **Snapshot** | `openapi/v1.json`, sxemaning saqlangan nusxasi. API kutilmaganda o'zgarsa, test xato beradi |

## 5. Retseptlar: "X qilmoqchiman"

Eng oson yo'l menga (Claude'ga) aytish: "directory'ga o'xshatib `buildings`
qo'sh". Quyidagi ro'yxat esa nima qilinishini tushunishingiz va o'zgarishni
tekshirishingiz uchun.

### Yangi jadval va uning API'si (masalan, binolar)

`app/directory/` papkasini namuna qilib oling. Tartib:

1. **Model.** Yangi papka va `models.py` yarating (`app/directory/models.py`ga
   o'xshatib).
2. **Modelni Alembic'ga tanitish.** `migrations/env.py`ga `import app.<papka>.models`
   qatorini qo'shing.
3. **Migratsiya.** `uv run alembic revision --autogenerate --rev-id 0007 -m "buildings"`
   buyrug'i faylni o'zi yozadi. Uni ochib tekshiring, keyin
   `uv run alembic upgrade head` bilan lokal bazaga qo'llang.
4. **Schemas.** `schemas.py`: `...Out` (javob), `...Create` (yaratish),
   `...Update` (tahrirlash).
5. **Service.** `service.py`: ro'yxat, bitta yozuv, yaratish, tahrirlash va
   o'chirish. Har bir o'zgarish audit'ga yoziladi (`self._audit(...)`).
6. **Ruxsatlar.** `app/rbac/permissions.py`dagi `CORE_PERMISSIONS`ga
   `admin:buildings:read` va `admin:buildings:write` qo'shing.
7. **Endpoint'lar.** `app/api/v1/buildings.py`. Har bir endpoint'da
   `require("...")` va `operation_id="admin_buildings_<amal>"` bo'lsin.
8. **Ulash.** `app/main.py`da `app.include_router(buildings.router)` qo'shing,
   lifespan ichida esa `app.state.building_service = ...` yozing.
9. **Testlar.** `tests/buildings/test_api.py` (`tests/directory/test_api.py`ga
   o'xshatib). `tests/conftest.py`dagi `TRUNCATE` qatoriga yangi jadvalni
   qo'shing, aks holda testlar bir-biriga xalaqit beradi.
10. **Sxemani yangilash.** `UPDATE_OPENAPI_SNAPSHOT=1 uv run pytest tests/api/test_openapi.py`
11. **Tekshiruvlar** (6-bo'lim), keyin commit va push.
12. **Serverda:** `admin-bff update`. U kodni yangilaydi, migratsiyani bajaradi
    va servisni qayta yuklaydi.

### Mavjud jadvalga ustun qo'shish

1. Ustunni modelga qo'shing (masalan, `app/directory/models.py`).
2. Yangi migratsiya yarating (yuqoridagi 3-qadam).
3. Ustun API'da ko'rinishi yoki o'zgarishi kerak bo'lsa, uni `...Out`,
   `...Create` va `...Update` schema'lariga qo'shing.
4. Service'da yangi maydon saqlanishini va audit'ga tushishini tekshiring
   (`_region_state` kabi funksiyalar).
5. Test yozing, sxemani yangilang, tekshiruvlarni o'tkazing.

### Yangi ruxsat qo'shish

1. `app/rbac/permissions.py`dagi `CORE_PERMISSIONS`ga yozing. O'zbekcha
   tavsif majburiy.
2. Ilova ishga tushganda ruxsat `permissions` jadvaliga o'zi yoziladi.
3. `superadmin`da u avtomatik bor (`*:*:*`). Boshqa rollarga uni adminkadan
   qo'shasiz.

### Xato matnini o'zgartirish

* Bitta funksiyaga tegishli matnlar o'sha funksiyaning service faylida turadi,
  masalan `app/directory/service.py` boshidagi `REGION_TAKEN`.
* Umumiy matnlar ("Bu amal uchun ruxsat yo'q" kabi) `app/core/errors.py`da.
* Xato kodini (`code`) o'zgartirmang: frontend mantiqni shunga qarab quradi.

### Serverda nimadir ishlamasa

```bash
admin-bff status                               # servislar va /ready holati
journalctl -u admin-bff -n 50 --no-pager       # oxirgi loglar: xato shu yerda
curl -s -H 'Host: kpi.uzbmb.uz' http://127.0.0.1:8080/health   # nginx orqali
```

* `/ready`da `"db": "error"` bo'lsa, bazaga ulanib bo'lmayapti.
  `/etc/admin-bff/admin-bff.env`dagi `DB_*` qiymatlarini va DB parolini
  tekshiring.
* `"redis": "error"` bo'lsa, `systemctl status admin-bff-redis` buyrug'i bilan
  Redis holatini ko'ring.
* Batafsil: [`docs/deploy.md`](deploy.md).

## 6. Tekshiruvlar

| Buyruq | Nimani tekshiradi |
| --- | --- |
| `uv run pytest` | Hamma narsa kutilganidek ishlaydimi (370 dan ortiq test, lokal PostgreSQL va Redis kerak) |
| `uv run ruff check .` | Kod qoidalari: ishlatilmagan import, xavfli usullar va boshqalar |
| `uv run ruff format --check .` | Kod bir xil uslubda yozilganmi (`--check`siz ishga tushirsangiz, o'zi tuzatadi) |
| `uv run mypy --strict app/ tests/ scripts/` | Tiplar mosmi (masalan, son kutilgan joyga matn berilmaganmi) |

Ishga tushirishdan oldin `unset VIRTUAL_ENV` qiling (README, "Tekshiruvlar").
To'rttalasi ham o'tsa, o'zgarishni push qilsa bo'ladi.

## Ilova: har bir fayl bir qatorda

### `app/api/`

| Fayl | Vazifasi |
| --- | --- |
| `health.py` | `/health` (servis tirikmi) va `/ready` (baza va Redis ishlayaptimi) |
| `docs.py` | Swagger sahifasi va OpenAPI sxemasi. Production'da sxema `admin:api:docs` bilan ochiladi |
| `v1/auth.py` | Kirish, chiqish, parol almashtirish, sessiyalar ro'yxati, OneID |
| `v1/me.py` | `/api/v1/me`: joriy admin va uning ruxsatlari (frontend menyuni shundan quradi) |
| `v1/admin.py` | Adminlar, rollar va ruxsatlar ro'yxati |
| `v1/directory.py` | Hududlar va tashkilotlar |
| `v1/audit.py` | Audit log'ni ko'rish va CSV eksport |

### `app/auth/`

| Fayl | Vazifasi |
| --- | --- |
| `service.py` | Kirish mantiqi: parolni tekshirish, sessiya ochish, bloklash, parol almashtirish |
| `sessions.py` | Sessiyalarni Redis'da saqlash, muddatini uzaytirish va o'chirish |
| `dependencies.py` | Cookie'dan sessiyani olish va CSRF token tekshiruvi (2-bo'lim, 7-8-qadamlar) |
| `csrf.py` | `Origin` tekshiruvi (2-bo'lim, 5-qadam) |
| `passwords.py` | Argon2 hash va parol qoidalari (kamida 12 belgi, keng tarqalgan parollar ro'yxati) |
| `lockout.py` | Xato urinishlarni sanash va bloklash (Redis) |
| `providers.py` | Kirish usullari: parol va OneID |
| `oneid.py` | OneID client'i (shablon, hali yozilmagan) |
| `tickets.py` | Bir martalik qisqa qiymatlar (OneID `state`) |
| `models.py` | `users` jadvali |
| `schemas.py` | Kirish endpoint'larining JSON maydonlari |
| `crypto.py` | Kichik shifrlash yordamchilari |
| `data/common_passwords.txt` | Taqiqlangan keng tarqalgan parollar |

### `app/rbac/`

| Fayl | Vazifasi |
| --- | --- |
| `permissions.py` | Ruxsatlar ro'yxati va wildcard (`*`) qoidalari |
| `registry.py` | Kodda e'lon qilingan barcha ruxsatlarni bir joyga yig'adi |
| `catalogue.py` | Ilova ishga tushganda ruxsatlarni `permissions` jadvaliga ko'chiradi |
| `dependencies.py` | `require("...")`: ruxsatni tekshiradi, rad etilganini audit'ga yozadi |
| `principal.py` | Admin va uning ruxsatlarini yuklaydi, Redis'da keshlaydi |
| `route_check.py` | Ruxsatsiz endpoint bo'lsa, ilovani ishga tushirmaydi |
| `service.py` | Adminlar va rollar: yaratish, tahrirlash, bloklash, rol berish, parolni tiklash |
| `models.py` | `roles`, `permissions`, `role_permissions`, `user_roles` jadvallari |
| `schemas.py` | `/me` va `/admin` endpoint'larining JSON maydonlari |

### `app/audit/`

| Fayl | Vazifasi |
| --- | --- |
| `sink.py` | Audit yozuvining tuzilishi (`AuditEvent`) |
| `writer.py` | Yozuvni bazaga yozadi (zanjirga ulab) |
| `chain.py` | Hash zanjiri: har bir yozuv oldingisiga bog'liq |
| `middleware.py` | Har bir POST, PATCH, DELETE va 403'ni yozib boradi (2-bo'lim, 3-qadam) |
| `context.py` | So'rov davomida "kim so'radi"ni eslab turadi |
| `service.py` | Audit'ni filtrlar bilan o'qish va CSV eksport |
| `verify.py` | Zanjir butunligini tekshirish |
| `models.py` | `audit_log` va `audit_anchors` jadvallari |
| `schemas.py` | Audit endpoint'larining JSON maydonlari |

### `app/core/`

| Fayl | Vazifasi |
| --- | --- |
| `db.py` | PostgreSQL'ga ulanish (PgBouncer va TLS sozlamalari ham shu yerda) |
| `db_privileges.py` | DB user'ning huquqlarini tekshirish va berish |
| `redis.py` | Redis'ga ulanish |
| `errors.py` | Yagona xato formati va xato kodlari |
| `pagination.py` | `?page=&page_size=` va noma'lum parametrlarni rad etish |
| `request_id.py` | So'rov ID'si va har bir so'rovning log qatori |
| `logging.py` | JSON loglar (journald'ga tushadi) |
| `body_limit.py` | 1 MB'dan katta body'ni rad etish |
| `ratelimit.py` | Cheklovlar (masalan, soatiga 5 ta eksport) |
| `metrics.py` | Prometheus metrikalari (`/metrics`, faqat server ichidan) |
| `pii.py` | Shaxsiy ma'lumotlarni maskalash |
| `guards.py`, `routes.py` | Ishga tushishdagi tekshiruvlar uchun yordamchilar |
| `time.py` | Vaqt (hammasi UTC'da) |

### Boshqa joylar

| Joy | Vazifasi |
| --- | --- |
| `migrations/env.py` | Alembic sozlamasi: bazaga qanday ulanish va qaysi modellarni ko'rish |
| `openapi/v1.json` | API sxemasining snapshot'i |
| `deploy/admin-bff.service` | systemd servisi (himoya sozlamalari bilan) |
| `deploy/admin-bff-redis.service`, `admin-bff-redis.conf` | BFF'ning alohida Redis'i |
| `deploy/gunicorn.conf.py` | Gunicorn sozlamalari (worker'lar soni, socket) |
| `deploy/deploy.sh`, `admin-bff.sh` | `admin-bff update`, `migrate`, `superadmin`, `status` buyruqlari |
| `deploy/nginx/` | Nginx sozlamalari: API (`admin-api.conf`), frontend (`admin-frontend.conf`), IP ro'yxati |
| `docs/frontend.md` | Frontend dasturchi uchun qo'llanma |
| `docs/deploy.md` | Serverga o'rnatish tartibi |
| `docs/security.md` | Xavfsizlik qarorlari |
