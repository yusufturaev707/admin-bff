# Xavfsizlik: qisqa threat model va qabul qilingan qarorlar

Hujjat bosqichma-bosqich to'ldiriladi. Hozir unda autentifikatsiya (1-bosqich)
va kalitlarni boshqarish bor.

## Nimadan himoyalanamiz

| Tahdid | Himoya |
| --- | --- |
| Parolni taxmin qilish, brute force | Argon2id. Username bo'yicha 5 ta xato urinishdan keyin 15 daqiqa blok, IP bo'yicha 10 daqiqada 20 xatodan keyin 30 daqiqa. Nginx'da ham `limit_req` bor |
| Hisob mavjudligini aniqlash (user enumeration) | Login topilmasa ham soxta hash tekshiriladi va xabar bir xil chiqadi. Mavjud bo'lmagan login ham xuddi shunday bloklanadi |
| Parol o'g'irlanishi | TOTP har doim talab qilinadi, OneID'dan keyin ham. Kodni qayta ishlatib bo'lmaydi |
| Sessiyani o'g'irlash yoki unga o'z ID'sini qo'yish | Sessiya serverda saqlanadi. Cookie `__Host-` prefiksli, `HttpOnly`, `Secure`, `SameSite=Strict`. Har login'da yangi ID beriladi. 30 daqiqa harakatsizlik yoki 12 soatdan keyin sessiya tugaydi |
| CSRF | `Origin` aynan frontend bilan solishtiriladi, `X-CSRF-Token` sessiyadagi token bilan `compare_digest` orqali tekshiriladi |
| DB yoki DB backup sizib chiqishi | Parol va recovery code Argon2id hash ko'rinishida. TOTP secret AES-256-GCM bilan shifrlangan, kalit DB'da emas. PINFL faqat HMAC hash sifatida saqlanadi |
| Log orqali sizib chiqish | Parol, kod, token va cookie log'ga yozilmaydi. PII maskalanadi. Mavjud bo'lmagan login audit'ga ochiq yozilmaydi, chunki ba'zan unga parol kiritib yuboriladi |

## Kalitlar

Barcha kalitlar `/etc/admin-bff/credentials/` papkasida turadi (`root:root
0600`). Servis ularni systemd `LoadCredential=` orqali oladi (11-bo'lim).
Kalitlar kodga, repo'ga, `.env`ga va DB backup'iga yozilmaydi.

| Kalit | Vazifasi | Yo'qolsa | Oshkor bo'lsa |
| --- | --- | --- | --- |
| `totp_enc_key` | TOTP secret'larini shifrlaydi | barcha adminlar TOTP'ni qaytadan ulaydi | rotatsiya qilinadi (pastda) |
| `pinfl_hmac_key` | OneID'da PINFL bo'yicha qidirish | barcha OneID bog'lanishlari qaytadan kiritiladi | rotatsiya qilinadi va PINFL'lar qaytadan biriktiriladi |
| `db_password`, `redis_password` | ulanish | PostgreSQL yoki Redis'da yangisi o'rnatiladi | xuddi shunday |

### Zaxira nusxa

Qaror: kalitlar DB backup'idan **alohida** saqlanadi. Shunda o'g'irlangan DB
backup'i bilan TOTP secret'larini ochib bo'lmaydi.

1. Kalit yaratilganda (yoki rotatsiyadan keyin) uning shifrlangan nusxasi
   olinadi:

   ```bash
   tar -C /etc/admin-bff -cf - credentials \
     | gpg --symmetric --cipher-algo AES256 -o admin-bff-keys-$(date +%F).tar.gpg
   ```

2. Fayl internetga ulanmagan ikkita tashuvchiga (USB) yoziladi va ikki xil
   seyfda saqlanadi. Seyflardan biri boshqa binoda bo'lsin.
3. `gpg` paroli faylning o'zidan alohida saqlanadi va boshqa mas'ul shaxsda
   turadi. Bitta odam kalitni yolg'iz tiklay olmasligi kerak.
4. Tiklash har yarim yilda bir marta staging'da sinab ko'riladi. Bu DB
   backup'ini oylik tiklash sinovi bilan birga qilinadi (11-bo'lim).
5. Kim, qachon va nima uchun zaxira nusxadan foydalangani yozib boriladi.

### `TOTP_ENC_KEY` rotatsiyasi

Rotatsiya uch holatda qilinadi:

- kalit oshkor bo'lganda yoki shunga shubha tug'ilganda;
- kalitga kirish huquqi bo'lgan xodim ishdan ketganda;
- boshqa hollarda yiliga bir marta.

Rotatsiya vaqtida adminlar ishdan uzilmaydi.

```bash
cd /etc/admin-bff/credentials
mv totp_enc_key totp_enc_key_previous
(umask 077; head -c 32 /dev/urandom | base64 > totp_enc_key)
# admin-bff.service'da: LoadCredential=totp_enc_key_previous:... qatorini oching
systemctl daemon-reload && systemctl restart admin-bff
sudo -u admin-bff ... python -m app.cli reencrypt-totp   # CREDENTIALS_DIRECTORY bilan, deploy.sh kabi
# "ochib bo'lmadi: 0" bo'lsa:
rm totp_enc_key_previous   # va LoadCredential qatorini yana yoping
systemctl daemon-reload && systemctl restart admin-bff
```

Rotatsiyadan keyin zaxira nusxa yangilanadi.

Texnik tafsilot: har bir shifrlangan qiymat ichida kalit identifikatori turadi
(kalitning SHA-256 prefiksi, kalitning o'zi emas). Shu sababli rotatsiya
davomida eski va yangi kalit bir vaqtda ishlaydi.

### `TOTP_ENC_KEY` yo'qolsa

Zaxira nusxa ham bo'lmasa:

1. Yangi kalit yaratiladi va servis qayta ishga tushiriladi.
2. `python -m app.cli reset-totp --all --yes` bajariladi. Barcha adminlarning
   TOTP'i va recovery code'lari o'chadi, sessiyalari tugaydi.
3. Adminlarga xabar beriladi. Keyingi kirishda ular parol (yoki OneID) bilan
   kiradi va TOTP'ni qaytadan ulaydi.

Bu vaqt oralig'ida kirish faqat bitta faktor (parol) bilan himoyalangan
bo'ladi. Shuning uchun:

- reset'dan keyin adminlar imkon qadar tezroq kirib, TOTP'ni ulashi kerak;
- audit log'da `auth.totp.enroll` hodisalari kuzatib boriladi.

Bitta admin telefonini yo'qotsa va recovery code'lari ham qolmagan bo'lsa,
`reset-totp --username <login>` ishlatiladi. Keyinchalik buni superadmin
adminkadan ham qila oladigan bo'ladi (2-bosqich).

Kalit noto'g'ri sozlansa, TOTP tekshiruvi `500 internal_error` qaytaradi va
log'ga `totp_secret_undecryptable` yoziladi. Bu adminning xato urinishi
hisoblanmaydi. Tizim "fail closed" ishlaydi: kirishga ruxsat berilmaydi.
