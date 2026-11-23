# Frontend uchun qo'llanma

Frontend faqat BFF API bilan ishlaydi. Sxema: `/api/v1/openapi.json`
(production'da yopiq), repo'dagi nusxasi: `openapi/v1.json`. Client'ni sxemadan
`openapi-typescript` yoki `orval` bilan generatsiya qiling.

Bu hujjatda hozircha autentifikatsiya qismi bor (1-bosqich). Meta
endpoint'lar va permission'lar keyingi bosqichlarda qo'shiladi.

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
| `rate_limited` | 429 | `Retry-After` soniya kutish |
| `method_not_allowed` | 405 | client'dagi xato: endpoint bu HTTP metodni qabul qilmaydi, `Allow` sarlavhasiga qarang |
| `internal_error` | 500 | "Ichki xatolik" va `request_id`ni ko'rsatish |
