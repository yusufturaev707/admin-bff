# Serverga o'rnatish (Debian 12)

Bu hujjat Admin BFF'ni Debian 12 (bookworm) serveriga birinchi marta
o'rnatish tartibi. Keyingi yangilashlar uchun `deploy/deploy.sh` ishlatiladi
(oxirgi bo'lim).

Ikkita server ishtirok etadi:

- **BFF serveri:** BFF, uning Redis'i va Nginx. Bu server boshqa tizim
  (proktoring) bilan umumiy.
- **DB serveri:** BFF'ning PostgreSQL bazasi. BFF unga tarmoq orqali TLS bilan
  ulanadi (5-qadam). Bu serverda boshqa bazalar ham bo'lishi mumkin.

Ikkala server ham umumiy bo'lgani uchun quyidagi qoidalarga amal qilinadi:

- **Boshqa tizimlarning servislariga tegilmaydi.** BFF serveridagi
  `redis-server.service`, PostgreSQL 15 klasteri va mavjud Nginx saytlari
  o'zgartirilmaydi va qayta ishga tushirilmaydi. BFF o'z Redis instansini
  ishlatadi. DB serverida faqat yangi rollar, yangi baza va `pg_hba.conf`ga
  qatorlar qo'shiladi.
- **Faqat aniq servislar boshqariladi.** `systemctl restart nginx`,
  `systemctl restart postgresql` va `systemctl restart redis-server` buyruqlari
  ishlatilmaydi. Nginx faqat `nginx -t`dan keyin `reload` qilinadi. DB serverida
  o'zgarishlar `pg_reload_conf()` bilan o'qiladi, PostgreSQL qayta ishga
  tushirilmaydi.
- **Og'ir ishlar imtihon smenasidan tashqarida qilinadi.** Bu Python'ni yig'ish
  (1-qadam).
- **UFW o'zgartirilmaydi.** BFF yangi port ochmaydi: tashqaridan unga faqat
  mavjud Nginx'ning 443-porti orqali kiriladi. Proktoringning portlarini bilmasdan
  UFW'ni yoqish yoki o'zgartirish uni ishdan chiqarishi mumkin.
- **Hamma buyruqlar root sifatida, `su -` yoki `sudo -i` bilan.** Oddiy `su`
  `PATH`ga `/usr/sbin`ni qo'shmaydi, shunda `nginx` va `useradd` topilmaydi.

## 0. Oldindan kerak bo'ladigan ma'lumotlar

- Domenlar. Configlarda namuna sifatida `admin.uzbmb.uz` va `admin-api.uzbmb.uz`
  turibdi (10-bo'lim).
- Shu domenlar uchun TLS sertifikati va kaliti. Proktoringda `*.uzbmb.uz`
  wildcard sertifikati bo'lsa, o'shani ishlatish mumkin.
- IP allowlist: adminlar kompyuterlarining IP diapazonlari. Ro'yxat bo'sh
  bo'lsa, Nginx hammani rad etadi.
- Adminlar kompyuterlarining `hosts` fayli:
  `<server_IP> admin.uzbmb.uz admin-api.uzbmb.uz`.
- DB serveri:
  - ichki IP manzili (`<DB_IP>`) va BFF serverining IP manzili (`<BFF_IP>`);
  - unda root huquqi;
  - PostgreSQL versiyasi 16 yoki undan yangi (lokal testlar 17'da o'tadi).

BFF serverida tekshirib oling:

```bash
grep -n "include" /etc/nginx/nginx.conf          # sites-enabled/* ulanganmi
grep -rn "listen" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
ss -ltnp | grep -E ':8081\b'                   # bo'sh bo'lishi kerak
```

Agar proktoring `listen 10.x.x.x:443 ssl;` kabi aniq IP bilan tinglasa,
BFF'ning server bloklarida ham `listen` xuddi shu ko'rinishda bo'lishi kerak.
Aks holda nginx shu IP'ga kelgan so'rovlarni proktoringning server blokiga
yuboradi.

## 1. Python 3.12

Tizimning o'z `python3` (3.11) buyrug'i o'zgarmaydi: `make altinstall` faqat
`/usr/local/bin/python3.12`ni qo'shadi.

```bash
apt install -y build-essential pkg-config libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncurses-dev \
  libgdbm-dev tk-dev uuid-dev xz-utils gnupg dirmngr curl git

cd /usr/local/src
curl -fLO https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz
curl -fLO https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz.asc
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys A821E680E5FA6305
gpg --verify Python-3.12.16.tar.xz.asc Python-3.12.16.tar.xz   # "Good signature from Thomas Wouters"

tar xf Python-3.12.16.tar.xz && cd Python-3.12.16
./configure --enable-optimizations --with-lto
nice -n 19 make -j8          # 15–30 daqiqa
make altinstall              # "make install" EMAS

python3 -V                   # Python 3.11.2, o'zgarmagan
python3.12 -c "import ssl, ctypes, sqlite3, lzma; print(ssl.OPENSSL_VERSION)"
```

`make` oxirida "necessary bits ... were not found" ro'yxatida `_ssl`,
`_ctypes`, `_sqlite3`, `_lzma` bo'lmasligi kerak.

Python `/root` yoki boshqa uy papkasiga o'rnatilmaydi: servis `ProtectHome=yes`
bilan ishlaydi va u yerni ko'rmaydi.

## 2. uv

`deploy.sh` uv'ni `/usr/local/bin/uv` manzilida kutadi.

```bash
curl -LsSf https://astral.sh/uv/install.sh -o /tmp/uv-install.sh
env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh /tmp/uv-install.sh
uv python find 3.12          # /usr/local/bin/python3.12
```

## 3. Tizim user'lari va kod

```bash
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin admin-bff
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin admin-bff-redis
usermod -aG admin-bff www-data           # Nginx BFF socket'iga guruh orqali kiradi
usermod -aG admin-bff-redis admin-bff    # BFF o'z Redis socket'iga kiradi

git clone https://github.com/yusufturaev707/admin-bff.git /srv/admin-bff
cd /srv/admin-bff
UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --compile-bytecode
```

Kod root'ga tegishli bo'lib qoladi, servis uni faqat o'qiydi. Repo yopiq
bo'lsa, `git clone` uchun GitHub'da shu serverga faqat o'qish huquqi bilan
deploy key qo'shiladi.

## 4. Secret'lar

Parollar tasodifiy yaratiladi va faqat fayllarda turadi. Ularni qo'lda yozish
ham, ekranga chiqarish ham shart emas.

```bash
install -d -o root -g root -m 0755 /etc/admin-bff
install -d -o root -g root -m 0700 /etc/admin-bff/credentials
( cd /etc/admin-bff/credentials && umask 077
  for f in db_password db_owner_password redis_password; do
    head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > "$f"
  done
  head -c 32 /dev/urandom | base64 > pinfl_hmac_key )
ls -l /etc/admin-bff/credentials     # hammasi root root -rw-------
```

`pinfl_hmac_key`ning zaxira nusxasi olinadi: u yo'qolsa, adminlarga
biriktirilgan PINFL'lar qayta biriktiriladi (`docs/security.md`, "Kalitlar").

## 5. PostgreSQL (DB serverida)

BFF'ning bazasi alohida DB serverida turadi. BFF unga tarmoq orqali TLS bilan
ulanadi va sertifikatni tekshiradi (`DB_SSLMODE=verify-full`). Production
boshqa serverdagi bazaga shifrlanmagan ulanishni rad etadi, servis ishga
tushmaydi.

Boshqacha yozilmagan bo'lsa, bu qadamdagi buyruqlar **DB serverida** root
sifatida bajariladi.

### 5.1. Versiya va tarmoq

```bash
pg_lsclusters                                    # versiya: 16 yoki yangi
runuser -u postgres -- psql -Atc "show listen_addresses" -c "show ssl" -c "show port"
```

- **Versiya.** 15 yoki eski bo'lsa, davom etishdan oldin xabar bering.
- **`listen_addresses`.** U `*` yoki DB serverining ichki IP manzili bo'lishi
  kerak. Bu sozlama faqat PostgreSQL'ni qayta ishga tushirganda o'zgaradi, bu esa
  shu serverdagi boshqa bazalarni ham to'xtatadi. O'zgartirish kerak bo'lsa, DB
  serverining egasi bilan kelishiladi.
- **Firewall.** DB serverida firewall bo'lsa, 5432-port faqat BFF serveridan
  ochiladi: `ufw allow from <BFF_IP> to any port 5432 proto tcp`.

### 5.2. TLS sertifikati

BFF ikki narsani tekshiradi:

- sertifikat BFF ishonadigan CA bilan imzolangan;
- sertifikat aynan `DB_HOST` uchun berilgan, ya'ni IP manzil yoki nom
  sertifikatning `subjectAltName` maydonida bor.

**DB serverida tashkilot CA'si imzolagan sertifikat bo'lsa,** shu CA'ning
sertifikatini 5.5-qadamda BFF serveriga qo'ying va 5.3-qadamga o'ting.

**Bo'lmasa** (masalan, Debian'ning `ssl-cert-snakeoil` sertifikati), BFF
ulanishi uchun alohida CA va server sertifikati yaratiladi. `<DB_IP>` o'rniga
DB serverining ichki IP manzili yoziladi:

```bash
install -d -m 0700 /root/admin-bff-db-ca && cd /root/admin-bff-db-ca
openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650 \
  -subj "/CN=admin-bff-db-ca" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout ca.key -out ca.crt
openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj "/CN=<DB_IP>" \
  -keyout server.key -out server.csr
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=IP:<DB_IP>' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
  -extfile server.ext -out server.crt
openssl verify -CAfile ca.crt server.crt         # server.crt: OK
```

Sertifikatni PostgreSQL'ga ulash. `V`: `pg_lsclusters`dagi versiya, masalan 17:

```bash
V=17
install -m 0644 -o postgres -g postgres server.crt /etc/postgresql/$V/main/server.crt
install -m 0600 -o postgres -g postgres server.key /etc/postgresql/$V/main/server.key
pg_conftool $V main set ssl on
pg_conftool $V main set ssl_cert_file /etc/postgresql/$V/main/server.crt
pg_conftool $V main set ssl_key_file /etc/postgresql/$V/main/server.key
runuser -u postgres -- psql -Atc "select pg_reload_conf()"
runuser -u postgres -- psql -Atc "show ssl"      # on
```

- **Sertifikat almashishi shu DB serveriga ulanadigan hamma mijozga ta'sir
  qiladi.** `sslmode=require` yoki `prefer` bilan ulanadigan mijozlar
  ishlashda davom etadi. Eski sertifikatni tekshiradigan mijoz
  (`verify-ca`, `verify-full`) ulana olmay qoladi. Shuning uchun bu qadam DB
  serverining egasi bilan kelishib bajariladi.
- **`ca.key` maxfiy.** U faqat sertifikatni yangilash uchun kerak, uni
  `/root/admin-bff-db-ca`da yoki undan ham xavfsiz joyda saqlang. `ca.crt`
  esa ochiq ma'lumot, BFF serveriga shu nusxalanadi.
- **Sertifikat 825 kun amal qiladi.** Tugash sanasi:
  `openssl x509 -enddate -noout -in server.crt`. Muddat o'tsa, BFF bazaga
  ulana olmaydi. Undan oldin shu buyruqlar bilan yangi `server.crt` chiqariladi
  (`ca.key` o'sha qoladi).

### 5.3. Rollar va baza

Ikki rol kerak (README, "PostgreSQL rollari"). Parollar 4-qadamda BFF
serverida yaratilgan. Ularni BFF serverida ko'rib, DB serveridagi psql'ning
`\password` buyrug'iga kiritasiz.

BFF serverida:

```bash
cat /etc/admin-bff/credentials/db_owner_password; echo
cat /etc/admin-bff/credentials/db_password; echo
```

DB serverida:

```bash
runuser -u postgres -- psql -v ON_ERROR_STOP=1
```

```sql
CREATE ROLE admin_bff_owner LOGIN;
CREATE ROLE admin_bff LOGIN;
\password admin_bff_owner
\password admin_bff
CREATE DATABASE admin_bff OWNER admin_bff_owner;
-- Shu serverdagi boshqa rollar bu bazaga ulana olmasin:
REVOKE CONNECT, TEMPORARY ON DATABASE admin_bff FROM PUBLIC;
GRANT CONNECT ON DATABASE admin_bff TO admin_bff_owner, admin_bff;
\q
```

`\password` parolni ekranga chiqarmaydi. U serverga faqat parolning SCRAM
hash'ini yuboradi, shuning uchun parol PostgreSQL log'iga ham, psql tarixiga
ham tushmaydi.

### 5.4. `pg_hba.conf`

Bu qatorlar fayl boshida turishi kerak, chunki PostgreSQL birinchi mos kelgan
qatorni ishlatadi:

- **1-qator** BFF rollarini faqat o'z bazasiga, faqat BFF serveridan va faqat
  TLS bilan kiritadi.
- **Qolgan qatorlar** bu rollarni boshqa hamma joyda rad etadi: boshqa
  bazalarda, TLS'siz ulanishda va boshqa IP'lardan.

```bash
BFF_IP=<BFF_IP>
F=$(runuser -u postgres -- psql -Atc "show hba_file")
cp -p "$F" "$F.bak-admin-bff"
{
  echo "# Admin BFF: faqat o'z bazasi, faqat BFF serveridan, faqat TLS bilan."
  echo "hostssl  admin_bff  admin_bff_owner,admin_bff  $BFF_IP/32  scram-sha-256"
  echo "host     all        admin_bff_owner,admin_bff  0.0.0.0/0   reject"
  echo "host     all        admin_bff_owner,admin_bff  ::/0        reject"
  echo "local    all        admin_bff_owner,admin_bff              reject"
  echo
  cat "$F.bak-admin-bff"
} > "$F"
runuser -u postgres -- psql -Atc "select pg_reload_conf()"
runuser -u postgres -- psql -Atc "select line_number, error from pg_hba_file_rules where error is not null"
```

Oxirgi buyruq hech narsa chiqarmasligi kerak. Agar xato chiqsa, PostgreSQL
eski qoidalar bilan ishlashda davom etadi. Unda faylni
`cp -p "$F.bak-admin-bff" "$F"` bilan qaytarib, xatoni tuzating.

### 5.5. BFF serverida: CA sertifikati va tekshiruv

5.2-qadamdagi `ca.crt` (yoki tashkilot CA'sining sertifikati) BFF serveriga
nusxalanadi. Masalan, DB serverida `cat ca.crt` qilib, chiqishini BFF serverida
shu faylga yozish mumkin:

```bash
install -m 0644 -o root -g root /dev/null /etc/admin-bff/db-ca.crt
nano /etc/admin-bff/db-ca.crt                    # -----BEGIN CERTIFICATE----- ... END
openssl s_client -starttls postgres -connect <DB_IP>:5432 \
  -CAfile /etc/admin-bff/db-ca.crt -verify_ip <DB_IP> -verify_return_error \
  </dev/null 2>/dev/null | grep "Verify return code"
# Verify return code: 0 (ok)
```

`0 (ok)` chiqmasa, BFF ham ulana olmaydi. Odatda sababi shulardan biri:

- noto'g'ri CA fayli;
- sertifikatdagi IP `<DB_IP>` bilan mos emas;
- tarmoq yoki firewall ulanishni o'tkazmayapti.

## 6. Redis (BFF'ning o'z instansi)

Serverdagi `redis-server.service` boshqa tizimniki. BFF sessiyalari, principal
keshi va bloklash hisoblagichlari unda saqlanmaydi: bu Redis'ga yoza olgan har
kim o'ziga permission yozib qo'ya oladi. BFF'ning instansi faqat unix socket'da
ishlaydi va parol talab qiladi.

```bash
install -m 0640 -o root -g admin-bff-redis /srv/admin-bff/deploy/admin-bff-redis.conf /etc/admin-bff/redis.conf
printf 'requirepass %s\n' "$(cat /etc/admin-bff/credentials/redis_password)" >> /etc/admin-bff/redis.conf
cp /srv/admin-bff/deploy/admin-bff-redis.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now admin-bff-redis
systemctl status admin-bff-redis --no-pager
ls -l /run/admin-bff-redis/                       # srwxrwx--- admin-bff-redis admin-bff-redis redis.sock
redis-cli -s /run/admin-bff-redis/redis.sock ping # "NOAUTH Authentication required" (parol ishlayapti)
```

Log'da `vm.overcommit_memory` haqida ogohlantirish chiqishi mumkin. Bu butun
serverga tegishli sozlama, uni proktoring bilan kelishmasdan o'zgartirmang.

## 7. Sozlamalar

```bash
install -m 0640 -o root -g root /srv/admin-bff/deploy/admin-bff.env.example /etc/admin-bff/admin-bff.env
nano /etc/admin-bff/admin-bff.env
```

Tekshiriladigan qiymatlar:

- `FRONTEND_ORIGIN`: frontendning haqiqiy domeni;
- `DB_HOST`: `<DB_IP>` (yoki sertifikatdagi nom, u BFF serverida `/etc/hosts`
  orqali ochilishi kerak) va `DB_PORT`;
- `DB_SSLMODE=verify-full`, `DB_SSLROOTCERT=/etc/admin-bff/db-ca.crt`;
- `REDIS_URL`: `unix:///run/admin-bff-redis/redis.sock?db=0`.

## 8. Migratsiyalar va servis

```bash
cd /srv/admin-bff
( set -a; . /etc/admin-bff/admin-bff.env; set +a
  APP_ENV=production CREDENTIALS_DIRECTORY=/etc/admin-bff/credentials \
  .venv/bin/alembic upgrade head )

cp /srv/admin-bff/deploy/admin-bff.service /etc/systemd/system/
# Servis faqat localhost bilan gaplasha oladi (IPAddressDeny=any): DB serveri
# shu yerda qo'shiladi. Repo'dagi unit o'zgarmaydi.
install -d /etc/systemd/system/admin-bff.service.d
printf '[Service]\nIPAddressAllow=%s/32\n' '<DB_IP>' > /etc/systemd/system/admin-bff.service.d/db.conf
systemctl daemon-reload
systemctl enable --now admin-bff
systemctl status admin-bff --no-pager
curl -s --unix-socket /run/admin-bff/bff.sock http://localhost/ready   # {"status":"ok",...}
systemd-analyze security admin-bff
```

Servis ishga tushmasa, sababi `journalctl -u admin-bff -n 50 --no-pager`da
ko'rinadi. Ko'p uchraydigan sabablar:

- migratsiya qilinmagan;
- `DB_USER` audit jadvalini o'zgartira oladi (owner yoki superuser);
- Redis paroli `credentials/redis_password` bilan bir xil emas;
- DB'ga ulanib bo'lmayapti. Migratsiya o'tib, servis ulana olmasa, sabab
  `admin-bff.service.d/db.conf`dagi IP. Ikkalasi ham ulana olmasa, 5.5-qadamdagi
  `openssl` tekshiruvi, `pg_hba.conf` va DB serveridagi firewall tekshiriladi.

## 9. Birinchi superadmin

```bash
cd /srv/admin-bff
( set -a; . /etc/admin-bff/admin-bff.env; set +a
  APP_ENV=production CREDENTIALS_DIRECTORY=/etc/admin-bff/credentials \
  .venv/bin/python -m scripts.create_superadmin --username <login> )
```

Parol ikki marta so'raladi. Superadmin birinchi kirishda parolini almashtiradi.

## 10. Nginx

Proktoringning saytlari o'zgarmaydi, BFF uchun yangi server bloklari qo'shiladi.

```bash
cp /srv/admin-bff/deploy/nginx/admin-allowlist.conf /etc/nginx/snippets/
nano /etc/nginx/snippets/admin-allowlist.conf    # allow <diapazon>; ... deny all;

install -d -m 0750 /etc/nginx/tls/admin-api.uzbmb.uz
# fullchain.pem va privkey.pem shu papkaga (privkey.pem: root:root 0600)

cp /srv/admin-bff/deploy/nginx/admin-api.conf /srv/admin-bff/deploy/nginx/admin-bff-internal.conf \
  /etc/nginx/sites-available/
# Domen boshqa bo'lsa: admin-api.conf'da server_name va sertifikat yo'llari.
ln -s /etc/nginx/sites-available/admin-api.conf /etc/nginx/sites-enabled/
ln -s /etc/nginx/sites-available/admin-bff-internal.conf /etc/nginx/sites-enabled/

nginx -t && systemctl reload nginx
```

`nginx -t` xato bersa, `reload` qilinmaydi va proktoring eski config bilan
ishlashda davom etadi. Xatoni tuzatib, qaytadan `nginx -t` qilinadi.

Frontend build'i tayyor bo'lganda `admin-frontend.conf` xuddi shu tarzda
qo'shiladi. Build `/var/www/admin-frontend`ga joylanadi.

## 11. Tekshirish

```bash
curl -s http://127.0.0.1:8081/metrics | head    # metrikalar (faqat server ichidan)
journalctl -u admin-bff -f                       # loglar (JSON)
```

Allowlist'dagi admin kompyuteridan tekshiriladi:

- `https://admin-api.<domen>/health` 200 qaytaradi;
- `https://admin-api.<domen>/metrics` 404 qaytaradi;
- frontend orqali superadmin kiradi va parolini almashtiradi.

## 12. Keyingi yangilashlar

```bash
sudo /srv/admin-bff/deploy/deploy.sh
```

Skript `git pull`, `uv sync`, migratsiyalar, `systemctl reload admin-bff`
(sessiyalar uzilmaydi) va `/ready` tekshiruvini bajaradi.

Orqaga qaytarish:

```bash
cd /srv/admin-bff && git checkout <oldingi_commit>
UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --compile-bytecode
systemctl reload admin-bff
```

Yangi versiya migratsiya qo'shgan bo'lsa, eski kod yangi sxema bilan ishga
tushmaydi. Unda `alembic downgrade`dan oldin DB serverida bazaning nusxasi
olinadi: `runuser -u postgres -- pg_dump -Fc admin_bff > /root/admin_bff.dump`.

## Hozircha yo'q

- OneID: o'chiq, client yozilmagan (6-bo'lim).
- DB backup va audit retention: egasining qarori bilan qilinmaydi.
- Tizimlarga ulanish (service JWT, connector'lar, real-time): 4–8-bosqichlar.
