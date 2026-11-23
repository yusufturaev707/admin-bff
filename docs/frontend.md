# Frontend uchun qo'llanma

Frontend faqat BFF API bilan ishlaydi.

- **Swagger UI:** `/api/v1/docs`. Sxema: `/api/v1/openapi.json`, repo'dagi
  nusxasi: `openapi/v1.json`.
- **Kirish.** Development'da ikkalasi ham login'siz ochiladi. Production'da
  `admin:api:docs` ruxsati kerak: avval adminkaga kiring, keyin shu brauzerda
  API domenidagi `/api/v1/docs`ni oching.
- **Swagger'dan ishlash (development).** Sahifa tepasidagi panelga login,
  parol va TOTP kodni kiritib "Kirish"ni bosing. Shundan keyin "Try it out"
  barcha endpoint'larda ishlaydi, `X-CSRF-Token`ni sahifaning o'zi qo'shadi.
  - "Step-up" tugmasi TOTP kodni qayta yuboradi: `x-step-up` endpoint'lari
    uchun 5 daqiqa amal qiladi.
  - Birinchi kirishda panel qolgan qadamlarni ko'rsatadi. Ular
    `/auth/totp/enroll`, `/auth/totp/confirm` va `/auth/password` orqali
    Swagger'ning o'zida bajariladi.
  - Sahifani `http://localhost:8000` yoki HTTPS orqali oching. Boshqa
    `http://` manzilda (masalan, LAN IP orqali) brauzer `Secure` cookie'ni
    saqlamaydi va kirish ishlamaydi.
- **Production'da Swagger faqat o'qish uchun.** Undan POST, PUT va DELETE
  yuborib bo'lmaydi, chunki Origin tekshiruvi faqat frontend origin'ini qabul
  qiladi.
- **Har bir endpoint'da:**
  - `security`: `session` cookie kerakmi va yozish so'rovida `csrf` sarlavhasi;
  - `x-permissions`: kerakli permission (menyu va tugmalarni shunga qarab
    yashiring);
  - `x-step-up: true`: TOTP qayta so'raladi.
- **Client.** Sxemadan `openapi-typescript` yoki `orval` bilan generatsiya
  qiling.

Bu hujjatda autentifikatsiya (1-bosqich), ruxsatlar va adminlarni
boshqarish (2-bosqich) hamda audit log (3-bosqich) bor. Tizimlar uchun meta
endpoint'lar keyingi bosqichlarda qo'shiladi.

## Umumiy qoidalar

- **Cookie.** Har bir so'rov `credentials: 'include'` bilan yuboriladi.
  Sessiya `__Host-admin_session` cookie'sida turadi. U `HttpOnly`, ya'ni
  JavaScript uni o'qiy olmaydi va o'qishi kerak ham emas.
- **CSRF.** Har bir `POST`, `PUT`, `PATCH` va `DELETE` so'rovida
  `X-CSRF-Token` sarlavhasi bo'lishi shart. Token login javobida keladi. Uni
  faqat xotirada saqlang, `localStorage`ga yozmang. Sahifa yangilansa,
  `GET /api/v1/auth/session` tokenni qaytadan beradi.
- **Origin.** Brauzer `Origin` sarlavhasini o'zi qo'yadi. U `FRONTEND_ORIGIN`
  bilan aynan bir xil bo'lishi kerak, aks holda javob `403 csrf_failed`.
- **Vaqt.** Barcha vaqtlar ISO 8601 formatida, UTC'da keladi (`...Z`).
  Ekranda `Asia/Tashkent` vaqtiga o'tkazib ko'rsating.
- **Xato formati** hamma joyda bir xil:

```json
{"error": {"code": "csrf_failed", "message": "...", "request_id": "...", "details": {}}}
```

Dastur mantiqini `code`ga qarab quring. `message` foydalanuvchiga
ko'rsatiladigan o'zbekcha matn. Xato haqida xabar berilganda `request_id` kerak
bo'ladi, uni ham ko'rsating.

## Login va parol bilan kirish

1. Login va parol yuboriladi:

   ```http
   POST /api/v1/auth/login
   {"username": "operator_toshkent", "password": "..."}
   ```

   Javob `200 {"mfa_required": true, "mfa_token": "..."}`. Keyingi qadam TOTP
   kod. `mfa_token` 5 daqiqa amal qiladi va faqat bir marta ishlatiladi.
2. TOTP kod yuboriladi:

   ```http
   POST /api/v1/auth/mfa
   {"mfa_token": "...", "code": "123456"}
   ```

   Telefon yo'qolgan bo'lsa, `code` o'rniga `{"recovery_code": "ABCD-EFGH-..."}`
   yuboriladi. Javob
   `200 {"csrf_token": "...", "setup_required": false, "pending": []}`, sessiya
   cookie'si o'rnatiladi.

Xatolar:

| Holat | Javob |
| --- | --- |
| Login yoki parol noto'g'ri | `401 not_authenticated`. Login topilmasa ham, parol noto'g'ri bo'lsa ham xabar bir xil |
| Kod noto'g'ri | `422 validation_error`, `details.fields[0].type = "invalid_code"`. Foydalanuvchi MFA sahifasida qoladi |
| `mfa_token` eskirgan yoki ishlatilgan (5 marta noto'g'ri kod kiritilsa ham shunday bo'ladi) | `401 session_expired`. Login sahifasiga qayting |
| Juda ko'p xato urinish | `429 rate_limited`. `Retry-After` sarlavhasi necha soniya kutishni aytadi |

## Birinchi kirish

Yangi admin birinchi marta kirganda TOTP'ni ulaydi va parolini almashtiradi.

1. `POST /auth/login` javobi
   `{"mfa_required": false, "setup_required": true, "pending": ["totp_enrollment", "password_change"], "csrf_token": "..."}`
   bo'ladi va cheklangan sessiya ochiladi. Bu sessiyada faqat
   `/auth/totp/*`, `/auth/password`, `/auth/session` va `/auth/logout`
   ishlaydi. Boshqa endpoint'lar
   `403 forbidden` qaytaradi va `details.pending`da qolgan qadamlarni ko'rsatadi.
2. `POST /auth/totp/enroll` chaqiriladi. Javob `{"secret": "...", "otpauth_uri": "otpauth://totp/..."}`.
   `otpauth_uri`ni QR kod qilib chizing. QR kutubxonasi lokal bo'lsin, chunki
   ichki tarmoqda CDN ishlamaydi. Kod faqat shu oynada, bir marta ko'rsatiladi.
3. Admin ilovadagi kodni kiritadi: `POST /auth/totp/confirm {"code": "123456"}`.
   Javobda `recovery_codes` (10 ta kod) va **yangi** `csrf_token` keladi, chunki
   sessiya ID'si almashadi. Recovery kodlarni bir marta ko'rsatib, adminga
   saqlab qo'yishni ayting.
4. Parol almashtiriladi: `POST /auth/password`
   `{"old_password": "...", "new_password": "...", "code": "123456"}`.
   Ilovadagi kod yangilanguncha kuting (30 soniyagacha), chunki 3-qadamdagi
   kodni qayta ishlatib bo'lmaydi. Javob `204`. Parol almashganda **barcha**
   sessiyalar tugaydi, shuning uchun foydalanuvchini login sahifasiga qaytaring.

Yangi parol qoidalari:

- kamida 12 belgi bo'lishi;
- ichida login bo'lmasligi;
- keng tarqalgan parollar ro'yxatida bo'lmasligi;
- eski paroldan farq qilishi.

Xato bo'lsa, `422` javobidagi `details.fields[0].type` qiymatlari:

- `password_too_short`, `password_too_long`;
- `password_contains_username`;
- `password_too_common`;
- `password_reused`;
- `invalid_password` (joriy parol noto'g'ri);
- `invalid_code`.

## OneID orqali kirish

OneID hozircha shablon. Backend'da u o'chiq, yoqilmaguncha endpoint'lar `404`
qaytaradi. Frontend uchun oqim tayyor:

1. "OneID orqali kirish" tugmasi bosilganda brauzer API'ga o'tadi:
   `window.location.href = API + "/api/v1/auth/oneid/start"`. Bu `fetch` emas.
2. OneID'dan keyin BFF brauzerni frontendning quyidagi sahifalaridan biriga
   qaytaradi:
   - `/login/mfa#mfa_token=...`: TOTP sahifasi. Token URL fragment'ida keladi,
     ya'ni serverga va log'larga tushmaydi. Uni o'qing, darhol
     `history.replaceState` bilan manzildan olib tashlang, keyin parol bilan
     kirishdagi kabi `POST /auth/mfa`ga yuboring.
   - `/login/setup`: birinchi kirish. Sessiya cookie'si o'rnatilgan bo'ladi.
     `csrf_token`ni `GET /auth/session`dan oling.
   - `/login?error=oneid_failed`: kirib bo'lmadi. Sababi ko'rsatilmaydi.
     Admin OneID'ni superadmin biriktirgan hisob bilan ishlatishi kerak.

## Sessiya

- `GET /auth/session` joriy sessiya ma'lumotini qaytaradi:
  - `username`;
  - `auth_method`;
  - `expires_at`;
  - `mfa_at`;
  - `pending`;
  - `csrf_token`.
- Sessiya ikki holatda tugaydi:
  - 30 daqiqa harakatsizlikdan keyin (har bir so'rov muddatni uzaytiradi);
  - kirgandan 12 soat o'tgach, qanday ishlatilganidan qat'i nazar.

  Tugagan sessiya `401 session_expired` qaytaradi. Shunda login sahifasiga
  qayting.
- `GET /auth/sessions` adminning faol sessiyalari ro'yxatini beradi.
  `DELETE /auth/sessions/{id}` sessiyani tugatadi. Joriy sessiya tugatilsa, bu
  logout bilan bir xil.
- `POST /auth/logout` javobi `204`.

## Step-up (xavfli amallar)

Xavfli amal oldidan admin TOTP kodni qayta kiritishi kerak bo'lishi mumkin:

1. Amal `401 step_up_required` qaytaradi.
2. TOTP oynasini oching va kodni yuboring: `POST /auth/step-up {"code": "123456"}`.
3. Javob `200` bo'lsa, amalni qaytadan yuboring.

Step-up 5 daqiqa amal qiladi.

## Ruxsatlar va menyu: `GET /api/v1/me`

Kirgandan keyin frontend `GET /api/v1/me`ni chaqiradi va menyuni shu javobga
qarab quradi:

```json
{
  "id": "...",
  "username": "operator_toshkent",
  "full_name": "Aliyev Vali",
  "roles": [{"id": "...", "name": "auditor"}],
  "permissions": ["admin:users:read", "faceid:*:read"],
  "scopes": [{"type": "region", "value": "*"}],
  "totp_enabled": true,
  "must_change_password": false,
  "mfa_at": "2026-11-23T09:15:02Z"
}
```

- **Permission formati** `tizim:resurs:amal`. Ro'yxatda wildcard ham bo'lishi
  mumkin: `faceid:*:read` Face-ID'dagi hamma narsani ko'rishni, `*:*:*` esa
  hamma narsani bildiradi. Tekshiruv: har bir qismi teng bo'lsa yoki `*` bo'lsa,
  ruxsat bor.
- **Tugmani yashirish faqat qulaylik uchun.** Haqiqiy tekshiruvni backend
  qiladi. Ruxsat bo'lmasa, javob `403 forbidden` bo'ladi.
- **Rollar darhol kuchga kiradi.** Superadmin rolni o'zgartirsa, keyingi
  so'rovdan boshlab yangi ruxsatlar ishlaydi. Adminning o'z rollari
  o'zgartirilsa, uning sessiyalari tugaydi va u qaytadan kiradi.

## Adminlarni boshqarish: `/api/v1/admin`

| Endpoint | Ruxsat |
| --- | --- |
| `GET /admin/users`, `GET /admin/users/{id}` | `admin:users:read` |
| `POST /admin/users`, `PATCH /admin/users/{id}` | `admin:users:write` |
| `PUT /admin/users/{id}/roles`, `PUT /admin/users/{id}/scopes` | `admin:users:write` |
| `POST /admin/users/{id}/reset-password`, `.../reset-totp`, `.../unlock` | `admin:users:security` |
| `GET /admin/roles`, `GET /admin/roles/{id}`, `GET /admin/permissions` | `admin:roles:read` |
| `POST /admin/roles`, `PATCH /admin/roles/{id}`, `DELETE /admin/roles/{id}` | `admin:roles:write` |

- **Step-up.** Barcha o'zgartiruvchi so'rovlar (`POST`, `PATCH`, `PUT`,
  `DELETE`) uchun TOTP so'nggi 5 daqiqa ichida kiritilgan bo'lishi kerak.
  Aks holda javob `401 step_up_required` bo'ladi. Shunda TOTP oynasini oching,
  kodni `POST /auth/step-up`ga yuboring va so'rovni qaytadan yuboring.
- **Vaqtinchalik parol.** Admin yaratilganda yoki parol tiklanganda javobda
  `initial_password` keladi. U faqat shu javobda, bir marta keladi: ko'rsating
  va saqlamang. Yangi admin birinchi kirishda TOTP'ni ulaydi va parolni
  almashtiradi.
- **Rol tahrirlash oynasi.** Ro'yxatni `GET /admin/permissions` beradi. Unda
  permission'lar tizimlar bo'yicha guruhlangan va har birining o'zbekcha
  tavsifi bor.
- **Rad etiladigan holatlar (`403`):**
  - admin o'zida yo'q permission yoki hududni boshqaga bera olmaydi;
  - o'z rollarini, hududlarini, kirish usullarini va holatini o'zgartira
    olmaydi;
  - o'zidan yuqori huquqli adminni boshqara olmaydi.
- **`409 conflict` holatlari:**
  - adminlarga biriktirilgan rolni o'chirib bo'lmaydi;
  - `superadmin` tizim roli o'zgarmaydi;
  - oxirgi faol superadminni bloklab ham, rolidan ayirib ham bo'lmaydi.
- **OneID.** Admin `auth_methods: ["oneid"]` bilan yaratilsa, `pinfl` majburiy.
  Javobda faqat maskalangan ko'rinishi keladi (`pinfl_masked`).

## Audit log: `/api/v1/audit`

Kim, qachon, nima qildi. Yozuvni hech kim o'zgartira olmaydi va o'chira
olmaydi. 90 kundan eski yozuvlar oylik bo'laklar bilan o'chiriladi.

| Endpoint | Ruxsat |
| --- | --- |
| `GET /audit` | `audit:logs:read` |
| `POST /audit/export` | `audit:logs:export` va step-up |

**Ro'yxat.** `GET /api/v1/audit?action=auth.login&outcome=denied&limit=50`.
Yangi yozuvlar birinchi keladi.

```json
{
  "items": [
    {
      "id": "1042",
      "ts": "2026-11-23T09:15:02.123456Z",
      "actor_id": "...",
      "actor_username": "superadmin",
      "actor_ip": "10.20.30.40",
      "action": "admin.user.roles",
      "system_id": "admin",
      "resource": "users",
      "resource_id": "...",
      "outcome": "success",
      "status_code": null,
      "request_id": "...",
      "before": ["auditor"],
      "after": ["auditor", "operator"],
      "details": {}
    }
  ],
  "next_cursor": "djE6MTA0Mg"
}
```

- **Filtrlar** aniq qiymat bo'yicha ishlaydi: `actor_id`, `actor_username`,
  `system_id`, `action`, `outcome` (`success`, `denied`, `error`), `resource`,
  `resource_id`, `request_id`. Vaqt oralig'i `from` va `to` bilan beriladi,
  timezone bilan (`...Z`). `from` oraliqqa kiradi, `to` kirmaydi.
- **Keyingi sahifa.** Javobdagi `next_cursor`ni `cursor` parametri sifatida
  yuboring, boshqa filtrlar o'zgarmasin. Oxirgi sahifada `next_cursor: null`.
  Jami son (`total`) qaytmaydi, chunki jadval katta.
- **Bitta ob'ektning tarixi:** `?resource=users&resource_id=<id>`. Masalan,
  admin sahifasida "O'zgarishlar tarixi" bo'limi.
- **Xatoni tekshirish.** Foydalanuvchi ko'rsatgan `request_id` bo'yicha
  `?request_id=...` shu so'rovning yozuvlarini topadi.
- **Ko'rsatish.** `action` qiymatlari: `auth.login`, `auth.logout`,
  `auth.step_up`, `auth.lockout`, `admin.user.create`, `admin.role.update`,
  `rbac.denied` (ruxsatsiz urinish), `http.request` va boshqalar.
  `http.request` xizmat o'zi yozmagan har bir yozish so'rovi va har bir `403`
  uchun yoziladi: unda `status_code` va `details.method`, `details.path`
  bo'ladi. `before` va `after`da shaxsiy ma'lumotlar maskalangan keladi.

**CSV eksport.** `POST /api/v1/audit/export`, body'da ro'yxatdagi filtrlar
(hammasi ixtiyoriy):

```http
POST /api/v1/audit/export
X-CSRF-Token: ...
{"action": "auth.login", "from": "2026-11-01T00:00:00Z", "to": "2026-11-23T00:00:00Z"}
```

- Bu POST so'rov, shuning uchun oddiy `<a href>` ishlamaydi. `fetch` bilan
  yuboring, `response.blob()`ni oling va `URL.createObjectURL` orqali
  yuklab bering. Fayl nomi `Content-Disposition` sarlavhasida keladi.
- TOTP so'nggi 5 daqiqada kiritilgan bo'lishi kerak, aks holda
  `401 step_up_required`.
- Bir soatda ko'pi bilan 5 ta eksport. Oshsa `429 rate_limited` va
  `Retry-After`.
- Bitta faylda ko'pi bilan 100 000 yozuv. Ko'p bo'lsa
  `422 validation_error`, `details.fields[0].type = "too_many_rows"`:
  foydalanuvchiga filtrlarni toraytirishni ayting.
- Fayl UTF-8 (BOM bilan, Excel to'g'ri ochadi), eski yozuvlar birinchi.
- Har bir eksportning o'zi ham audit'ga yoziladi.

## Ro'yxatlar

- **Pagination:** `?page=1&page_size=50`, `page_size` 100 dan oshmaydi. Javob
  `{"items": [...], "page": 1, "page_size": 50, "total": 120}`.
- **Katta jadvallar** (audit) cursor bilan: `?cursor=&limit=50`, javobda
  `next_cursor`.
- **Saralash:** `?sort=username` yoki `?sort=-created_at` (minus kamayish
  tartibini bildiradi).
- **Noma'lum parametr** `422` qaytaradi, `details.fields[0].type` esa
  `"unknown_parameter"` bo'ladi. Shu sababli filtr nomidagi xato e'tiborsiz
  qolib, filtrlanmagan ma'lumot qaytmaydi.

## Xato kodlari

Hamma joyda ishlatiladigan kodlar shu jadvalda. Keyingi bosqichlarda
`not_found`, `system_unavailable`, `upstream_error` va `internal_error`
haqida ham batafsil yoziladi.

| `code` | Status | Frontend nima qiladi |
| --- | --- | --- |
| `not_authenticated` | 401 | login sahifasi |
| `session_expired` | 401 | login sahifasi |
| `step_up_required` | 401 | TOTP oynasi, keyin amalni qayta yuborish |
| `csrf_failed` | 403 | `csrf_token`ni `GET /auth/session`dan yangilab qayta urinish |
| `forbidden` | 403 | `details.pending` bo'lsa, sozlash sahifasi; aks holda "ruxsat yo'q" |
| `validation_error` | 422 | `details.fields` bo'yicha formadagi maydon xatolari |
| `conflict` | 409 | masalan, TOTP allaqachon ulangan |
| `rate_limited` | 429 | `Retry-After` soniya kutish. Bitta sessiyadan daqiqasiga 300 tadan ortiq so'rov ham shunday javob oladi: so'rovlarni tsiklda takrorlamang |
| `method_not_allowed` | 405 | client'dagi xato: endpoint bu HTTP metodni qabul qilmaydi, `Allow` sarlavhasiga qarang |
| `internal_error` | 500 | "Ichki xatolik" va `request_id`ni ko'rsatish |
