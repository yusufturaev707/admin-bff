# Serverga o'rnatish (Ubuntu 22.04)

Bu hujjat Admin BFF'ni Ubuntu 22.04 LTS (jammy) serveriga birinchi marta
o'rnatish tartibi. Keyingi yangilashlar uchun `deploy/deploy.sh` ishlatiladi
(12-bo'lim).

> **Ubuntu 22.04'ning standart xavfsizlik yangilanishlari 2027-yil bahorida
> tugaydi.** Undan keyin yangilanishlar faqat Ubuntu Pro bilan keladi. Server
> 24.04'ga o'tkazilganda 1- va 6-qadamlar qayta ko'rib chiqiladi: 24.04'da
> Python 3.12 tizimning o'zida bor.

Ikkita server ishtirok etadi:

- **BFF serveri:** BFF, uning Redis'i va Nginx. Bu serverda boshqa loyihalar
  ham ishlaydi.
- **DB serveri:** BFF'ning PostgreSQL bazasi. BFF unga tarmoq orqali ulanadi
  (5-qadam), DB serverida hech narsa o'zgartirilmaydi.

BFF serveri umumiy bo'lgani uchun quyidagi qoidalarga amal qilinadi:

- **Boshqa loyihalarning servislariga tegilmaydi.** BFF serveridagi Redis,
  PostgreSQL, Nginx saytlari va boshqa servislar o'zgartirilmaydi va qayta
  ishga tushirilmaydi. BFF'ning Python'i va Redis'i tizim paketlaridan alohida
  o'rnatiladi (1- va 6-qadamlar), shuning uchun boshqa loyihalarning paketlari
  yangilanmaydi.
- **Faqat aniq servislar boshqariladi.** `systemctl restart nginx`,
  `systemctl restart postgresql` va `systemctl restart redis-server` buyruqlari
  ishlatilmaydi. Nginx faqat `nginx -t`dan keyin `reload` qilinadi.
- **apt servislarni o'zi qayta ishga tushirmaydi.** Ubuntu 22.04'da
  `apt install`dan keyin `needrestart` ishlaydi. U kutubxonasi yangilangan
  servislarni qayta ishga tushirishni taklif qiladi, ular orasida boshqa
  loyihalarniki ham bo'ladi. Shuning uchun bu hujjatdagi har bir `apt` buyrug'i
  `NEEDRESTART_MODE=l` bilan bajariladi: needrestart faqat ro'yxatni
  ko'rsatadi. `apt upgrade` deploy'ning qismi emas.
- **Og'ir ishlar serverdagi boshqa loyihalar kam yuklangan vaqtda qilinadi.**
  Bu Python va Redis'ni yig'ish (1- va 6-qadamlar). Ular `nice -n 19` bilan va
  yadrolarning yarmida (ko'pi bilan 16 tasida) ishlaydi.
- **UFW o'zgartirilmaydi.** BFF yangi port ochmaydi: tashqaridan unga faqat
  Nginx'ning 443-porti orqali kiriladi. Boshqa loyihalarning portlarini
  bilmasdan UFW'ni yoqish yoki o'zgartirish ularni ishdan chiqarishi mumkin.
- **Hamma buyruqlar root sifatida, `sudo -i` bilan bajariladi.**

## 0. Oldindan kerak bo'ladigan ma'lumotlar

- Domenlar. Configlarda namuna sifatida `admin.uzbmb.uz` va `admin-api.uzbmb.uz`
  turibdi (10-bo'lim).
- Shu domenlar uchun TLS sertifikati va kaliti. Serverda boshqa loyihaning
  `*.uzbmb.uz` wildcard sertifikati bo'lsa, o'shani ishlatish mumkin.
- IP allowlist: adminlar kompyuterlarining IP diapazonlari. Ro'yxat bo'sh
  bo'lsa, Nginx hammani rad etadi.
- Adminlar kompyuterlarining `hosts` fayli:
  `<server_IP> admin.uzbmb.uz admin-api.uzbmb.uz`.
- DB'ga ulanish ma'lumotlari: host (`<DB_IP>`), port, baza nomi, user va
  parol (5-qadam).

BFF serverida tekshirib oling. Bu buyruqlar hech narsani o'zgartirmaydi:

```bash
lsb_release -ds; systemctl --version | head -1; openssl version
nproc; free -h; df -h /srv /opt /usr/local
ss -ltnp | grep -E ':(80|443|18081)\b' | cut -c1-120   # 80 va 443 kimda; 18081 bo'sh bo'lishi kerak
nginx -v                                         # nginx bormi va versiyasi
grep -n "include" /etc/nginx/nginx.conf          # sites-enabled/* ulanganmi
grep -rn "listen" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
grep -rn "default_server" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
```

Natijaga qarab:

- **80 va 443-portlar.** Ularni nginx'dan boshqa dastur (`apache2`, `caddy` va
  boshqalar) egallagan bo'lsa, davom etilmaydi: BFF'ning config'lari nginx
  uchun yozilgan.
- **nginx o'rnatilmagan bo'lsa** (80 va 443 ham bo'sh), Ubuntu'niki
  o'rnatiladi. Uning namuna sayti o'chiriladi, chunki u 80-portda
  "Welcome to nginx" sahifasini ko'rsatadi:

  ```bash
  NEEDRESTART_MODE=l apt install -y nginx
  rm /etc/nginx/sites-enabled/default && nginx -t && systemctl reload nginx
  ```

- **HTTP/2.** Ubuntu 22.04'ning nginx'i 1.18, unda `listen ... http2` butun
  ip:port uchun ishlaydi. BFF config'larida `listen 443 ssl http2;` turibdi,
  chunki serverda `api-iiv.uzbmb.uz` uni `0.0.0.0:443`da allaqachon yoqqan.
  `grep`da 443-portli hech bir qatorda `http2` bo'lmasa,
  `admin-api.conf` va `admin-frontend.conf`dagi `http2` olib tashlanadi: aks
  holda u boshqa saytlarda ham HTTP/2'ni yoqadi. nginx 1.25.1 yoki yangisida
  `listen`dagi `http2` o'rniga `http2 on;` yoziladi.
- **IPv6.** BFF config'larida `listen [::]` yo'q, chunki boshqa saytlar faqat
  IPv4'da tinglaydi. Ular IPv6'da ham tinglasa (`grep`da `[::]`), BFF'ga ham
  xuddi shunday qatorlar qo'shiladi.
- **Default server.** `default_server` hech qayerda yo'q bo'lsa, har bir
  ip:port'da `sites-enabled`dagi alifbo bo'yicha birinchi sayt default server
  bo'ladi: IP orqali yoki noma'lum domen bilan kelgan so'rovlar unga tushadi.
  BFF fayllari `sites-enabled`ga `zz-` bilan boshlanadigan nom bilan ulanadi
  (10-qadam), shunda default server o'zgarmaydi.
- **18081-port.** `admin-bff-internal.conf` (JWKS va `/metrics`, faqat
  `127.0.0.1`) shu portda tinglaydi. Band bo'lsa, boshqa bo'sh port tanlanadi
  va 11-qadamdagi `curl`da ham almashtiriladi.
- **Aniq IP bilan `listen`.** Boshqa loyiha `listen 10.x.x.x:443 ssl;` kabi
  aniq IP bilan tinglasa, BFF'ning server bloklarida ham `listen` xuddi shu
  ko'rinishda bo'lishi kerak. Aks holda nginx shu IP'ga kelgan so'rovlarni o'sha
  loyihaning server blokiga yuboradi.
- **Disk.** `/usr/local`da kamida 3 GB bo'sh joy kerak: Python va Redis
  manbalari va ularni yig'ish.

## 1. Python 3.12

Ubuntu 22.04'ning o'z `python3` buyrug'i 3.10. Unga tizimning o'zi (apt,
netplan, cloud-init) va boshqa loyihalar bog'langan, u o'zgarmaydi. Ubuntu
22.04 repo'larida Python 3.12 yo'q. deadsnakes PPA'si Ubuntu'ning rasmiy
repo'si emas, shuning uchun Python manbadan yig'iladi.

```bash
NEEDRESTART_MODE=l apt install -y build-essential pkg-config libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncurses-dev \
  libgdbm-dev tk-dev uuid-dev xz-utils gnupg dirmngr curl git

cd /usr/local/src
curl -fLO https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz
curl -fLO https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz.asc
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys A821E680E5FA6305
gpg --verify Python-3.12.16.tar.xz.asc Python-3.12.16.tar.xz   # "Good signature from Thomas Wouters"

tar xf Python-3.12.16.tar.xz && cd Python-3.12.16
./configure --enable-optimizations --with-lto
J=$(( $(nproc) > 32 ? 16 : ($(nproc) + 1) / 2 ))   # yadrolarning yarmi, ko'pi bilan 16
nice -n 19 make -j"$J"       # 20–60 daqiqa
make altinstall              # "make install" EMAS

python3 -V                   # Python 3.10.x, o'zgarmagan
python3.12 -c "import ssl, ctypes, sqlite3, lzma; print(ssl.OPENSSL_VERSION)"   # OpenSSL 3.0.x
```

`make install` ishlatilmaydi: u `/usr/local/bin/python3`ni ham yozadi, `PATH`da
esa `/usr/local/bin` `/usr/bin`dan oldin turadi. Shunda tizimning va boshqa
loyihalarning `python3` buyrug'i 3.12'ga almashib qoladi. `make altinstall`
faqat `/usr/local/bin/python3.12`ni qo'shadi.

`make` oxirida "necessary bits ... were not found" ro'yxatida `_ssl`,
`_ctypes`, `_sqlite3`, `_lzma` bo'lmasligi kerak.

Python `/root` yoki boshqa uy papkasiga o'rnatilmaydi: servis `ProtectHome=yes`
bilan ishlaydi va u yerni ko'rmaydi. U `apt` orqali yangilanmaydi, xavfsizlik
yangilanishlari 12-bo'limda.

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
UV_PYTHON_PREFERENCE=only-system UV_PYTHON_DOWNLOADS=never \
  uv sync --frozen --no-dev --compile-bytecode
.venv/bin/python -V                      # Python 3.12.16
readlink -f .venv/bin/python             # /usr/local/bin/python3.12
```

`readlink` `/root/...` yoki `/home/...` ko'rsatsa, servis `203/EXEC Permission
denied` bilan ishga tushmaydi: u uy papkalarini ko'rmaydi (`ProtectHome=yes`).
Unda `rm -rf .venv` qilinadi va `uv sync` shu buyruq bilan qaytadan bajariladi.

Kod root'ga tegishli bo'lib qoladi, servis uni faqat o'qiydi. Repo yopiq
bo'lsa, `git clone` uchun GitHub'da shu serverga faqat o'qish huquqi bilan
deploy key qo'shiladi.

## 4. Secret'lar

Redis paroli va PINFL kaliti tasodifiy yaratiladi va faqat fayllarda turadi.
Ularni qo'lda yozish ham, ekranga chiqarish ham shart emas. DB paroli
5-qadamda yoziladi.

```bash
install -d -o root -g root -m 0755 /etc/admin-bff
install -d -o root -g root -m 0700 /etc/admin-bff/credentials
( cd /etc/admin-bff/credentials && umask 077
  head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > redis_password
  head -c 32 /dev/urandom | base64 > pinfl_hmac_key )
ls -l /etc/admin-bff/credentials     # hammasi root root -rw-------
```

`pinfl_hmac_key`ning zaxira nusxasi olinadi: u yo'qolsa, adminlarga
biriktirilgan PINFL'lar qayta biriktiriladi (`docs/security.md`, "Kalitlar").

## 5. PostgreSQL (DB serveri)

BFF bazaga beshta qiymat bilan ulanadi: host, port, baza nomi, user va parol.
DB serverida hech narsa sozlanmaydi. To'rtta qiymat 7-qadamda `admin-bff.env`ga
yoziladi, parol esa shu yerda faylga yoziladi. Parol ekranga chiqmaydi va
shell tarixiga tushmaydi:

```bash
( umask 077; read -rsp 'DB paroli: ' P; echo
  printf '%s' "$P" > /etc/admin-bff/credentials/db_password; unset P )
```

Jadvallarni 8-qadamdagi migratsiyalar yaratadi. DB serverida TLS yoqilgan
bo'lsa, ulanish o'zi shifrlanadi. Migratsiyalar va servis bitta user bilan
ishlaydi (egasining qarori, 2026-11-24; `docs/security.md`).

## 6. Redis 7.4 (BFF'ning o'z instansi)

Serverdagi Redis (bo'lsa) boshqa loyihalarniki. BFF sessiyalari, principal
keshi va bloklash hisoblagichlari unda saqlanmaydi: bu Redis'ga yoza olgan har
kim o'ziga permission yozib qo'ya oladi. BFF'ning instansi faqat unix socket'da
ishlaydi va parol talab qiladi.

Redis ham manbadan yig'iladi:

- Ubuntu 22.04'ning `redis-server` paketi 6.0. U stack talabiga (Redis 7) mos
  emas va Redis'ning o'zi uni endi qo'llab-quvvatlamaydi.
- Redis'ning o'z apt repo'si (packages.redis.io) serverdagi `redis-server`
  paketini almashtiradi, ya'ni boshqa loyihalarning Redis'ini ham yangilab,
  qayta ishga tushiradi.

Yig'ilgan Redis `/opt/admin-bff-redis`ga o'rnatiladi. U tizim paketlariga ham,
`PATH`ga ham aralashmaydi: boshqa loyihalarning `redis-server` va `redis-cli`
buyruqlari o'zgarmaydi.

`V`: 7.4 qatoridagi eng oxirgi versiya, ro'yxati
https://download.redis.io/releases/ sahifasida. Bu hujjat yozilganda
(2026-yil noyabr) u 7.4.12 edi.

```bash
NEEDRESTART_MODE=l apt install -y build-essential pkg-config libsystemd-dev curl

cd /usr/local/src
V=7.4.12
curl -fLO https://download.redis.io/releases/redis-$V.tar.gz
curl -fsSL https://raw.githubusercontent.com/redis/redis-hashes/master/README -o redis-hashes.txt
grep " redis-$V.tar.gz " redis-hashes.txt | awk '{print $4 "  " $2}' | sha256sum -c   # redis-7.4.12.tar.gz: OK

tar xzf redis-$V.tar.gz && cd redis-$V
J=$(( $(nproc) > 32 ? 16 : ($(nproc) + 1) / 2 ))
nice -n 19 make -j"$J" USE_SYSTEMD=yes
make install PREFIX=/opt/admin-bff-redis USE_SYSTEMD=yes
/opt/admin-bff-redis/bin/redis-server --version   # Redis server v=7.4.12 ...
```

- **`sha256sum` `OK` demasa** yoki "no properly formatted checksum lines"
  desa, davom etilmaydi: fayl buzilgan yoki versiya noto'g'ri yozilgan.
- **`USE_SYSTEMD=yes`** servis `Type=notify` bilan ishlashi uchun kerak: Redis
  tayyor bo'lganini systemd'ga o'zi xabar qiladi.

Instansni sozlash va ishga tushirish:

```bash
install -m 0640 -o root -g admin-bff-redis /srv/admin-bff/deploy/admin-bff-redis.conf /etc/admin-bff/redis.conf
printf 'requirepass %s\n' "$(cat /etc/admin-bff/credentials/redis_password)" >> /etc/admin-bff/redis.conf
cp /srv/admin-bff/deploy/admin-bff-redis.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now admin-bff-redis
systemctl status admin-bff-redis --no-pager
ls -l /run/admin-bff-redis/      # srwxrwx--- admin-bff-redis admin-bff-redis redis.sock
/opt/admin-bff-redis/bin/redis-cli -s /run/admin-bff-redis/redis.sock ping   # "NOAUTH Authentication required" (parol ishlayapti)
```

Log'da `vm.overcommit_memory` haqida ogohlantirish chiqishi mumkin. Bu butun
serverga tegishli sozlama, uni boshqa loyihalar bilan kelishmasdan
o'zgartirmang.

## 7. Sozlamalar

Serverda sozlamalar bitta faylda turadi: `/etc/admin-bff/admin-bff.env`.
Servis uni systemd orqali o'qiydi (`EnvironmentFile=`). Production'da
`/srv/admin-bff/.env` o'qilmaydi, uni yaratish shart emas. Parollar bu faylga
emas, `/etc/admin-bff/credentials/` ichiga yoziladi (4- va 5-qadamlar).

```bash
install -m 0640 -o root -g root /srv/admin-bff/deploy/admin-bff.env.example /etc/admin-bff/admin-bff.env
nano /etc/admin-bff/admin-bff.env
```

Tekshiriladigan qiymatlar:

- `FRONTEND_ORIGIN`: frontendning haqiqiy domeni;
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`: DB'ga ulanish ma'lumotlari
  (5-qadam);
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
journalctl -u admin-bff -n 200 --no-pager | grep database_tls   # "encrypted": true yoki false
```

Log'dagi `audit_privileges_too_broad` ogohlantirishi kutilgan holat: bitta DB
user bilan ishlanadi (5-qadam).

Servis ishga tushmasa, sababi `journalctl -u admin-bff -n 50 --no-pager`da
ko'rinadi. Ko'p uchraydigan sabablar:

- migratsiya qilinmagan;
- Redis paroli `credentials/redis_password` bilan bir xil emas;
- DB'ga ulanib bo'lmayapti. Migratsiya o'tib, servis ulana olmasa, sabab
  `admin-bff.service.d/db.conf`dagi IP. Ikkalasi ham ulana olmasa, host, port,
  baza nomi, user va parol tekshiriladi (5- va 7-qadamlar).

## 9. Birinchi superadmin

```bash
cd /srv/admin-bff
( set -a; . /etc/admin-bff/admin-bff.env; set +a
  APP_ENV=production CREDENTIALS_DIRECTORY=/etc/admin-bff/credentials \
  .venv/bin/python -m scripts.create_superadmin --username <login> )
```

Parol ikki marta so'raladi. Superadmin birinchi kirishda parolini almashtiradi.

## 10. Nginx

Boshqa loyihalarning saytlari o'zgarmaydi, BFF uchun yangi server bloklari
qo'shiladi.

nginx `sites-enabled`dagi fayllarni alifbo tartibida o'qiydi. `default_server`
yozilmagan bo'lsa, ip:port'dagi birinchi server bloki default server bo'ladi:
IP orqali yoki noma'lum domen bilan kelgan so'rovlar unga tushadi. `admin-api`
alifboda boshqa saytlardan (`api-iiv...`, `exam...`) oldin keladi, shuning uchun
`sites-enabled`dagi nomlar `zz-` bilan boshlanadi. Shunda BFF bloklari oxirida
o'qiladi va boshqa loyihalarning default server'i o'zgarmaydi.

```bash
# Hozirgi holat: IP orqali kelgan so'rovga qaysi sayt javob beradi.
curl -s  -o /dev/null -w 'http  %{http_code}\n' http://127.0.0.1/
curl -sk -o /dev/null -w 'https %{http_code}\n' https://127.0.0.1/

cp /srv/admin-bff/deploy/nginx/admin-allowlist.conf /etc/nginx/snippets/
nano /etc/nginx/snippets/admin-allowlist.conf    # allow <diapazon>; ... deny all;

install -d -m 0750 /etc/nginx/tls/admin-api.uzbmb.uz
# fullchain.pem va privkey.pem shu papkaga (privkey.pem: root:root 0600)

cp /srv/admin-bff/deploy/nginx/admin-api.conf /srv/admin-bff/deploy/nginx/admin-bff-internal.conf \
  /etc/nginx/sites-available/
# Domen boshqa bo'lsa: admin-api.conf'da server_name va sertifikat yo'llari.
ln -s /etc/nginx/sites-available/admin-api.conf /etc/nginx/sites-enabled/zz-admin-api.conf
ln -s /etc/nginx/sites-available/admin-bff-internal.conf /etc/nginx/sites-enabled/zz-admin-bff-internal.conf

nginx -t && systemctl reload nginx

# Natija avvalgidek bo'lishi kerak:
curl -s  -o /dev/null -w 'http  %{http_code}\n' http://127.0.0.1/
curl -sk -o /dev/null -w 'https %{http_code}\n' https://127.0.0.1/
```

Natija o'zgargan bo'lsa (masalan, `403` chiqsa), BFF default server bo'lib
qolgan. Unda BFF bloklari darhol o'chiriladi va sababi aniqlanadi:
`rm /etc/nginx/sites-enabled/zz-admin-*.conf && nginx -t && systemctl reload nginx`.

`nginx -t` xato bersa, `reload` qilinmaydi va boshqa saytlar eski config bilan
ishlashda davom etadi. Xatoni tuzatib, qaytadan `nginx -t` qilinadi.

Frontend build'i tayyor bo'lganda `admin-frontend.conf` xuddi shu tarzda
(`zz-admin-frontend.conf` nomi bilan) qo'shiladi. Build `/var/www/admin-frontend`ga joylanadi.

## 11. Tekshirish

```bash
curl -s http://127.0.0.1:18081/metrics | head   # metrikalar (faqat server ichidan)
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
UV_PYTHON_PREFERENCE=only-system UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --compile-bytecode
systemctl reload admin-bff
```

Yangi versiya migratsiya qo'shgan bo'lsa, eski kod yangi sxema bilan ishga
tushmaydi. Unda `alembic downgrade`dan oldin bazaning nusxasi olinadi
(`pg_dump -Fc`).

### Python va Redis'ning xavfsizlik yangilanishlari

Ikkalasi ham manbadan yig'ilgan, shuning uchun `apt` ularni yangilamaydi.
Yangi versiyalar oyiga bir marta tekshiriladi: Python 3.12 uchun
https://www.python.org/downloads/, Redis 7.4 uchun
https://github.com/redis/redis/releases.

- **Python.** 1-qadam yangi versiya raqami bilan takrorlanadi. `make altinstall`
  `/usr/local/bin/python3.12`ni almashtiradi, `.venv` esa shu faylga bog'langan.
  Keyin `systemctl restart admin-bff` qilinadi. `reload` yetmaydi, chunki
  Gunicorn'ning asosiy jarayoni eski interpreter bilan qoladi. Sessiyalar
  Redis'da, ular uzilmaydi.
- **Redis.** 6-qadamdagi yig'ish yangi `V` bilan takrorlanadi: `make install`
  `/opt/admin-bff-redis/bin`ni almashtiradi. Keyin
  `systemctl restart admin-bff-redis` qilinadi. Redis to'xtashda ma'lumotlarini
  `dump.rdb`ga yozadi, shuning uchun sessiyalar saqlanib qoladi. Qayta ishga
  tushish paytidagi bir-ikki soniyada BFF so'rovlarga xato qaytarishi mumkin.

Eski manba papkalari (`/usr/local/src/Python-*`, `/usr/local/src/redis-*`)
keyin o'chiriladi.

## Hozircha yo'q

- OneID: o'chiq, client yozilmagan (6-bo'lim).
- DB backup va audit retention: egasining qarori bilan qilinmaydi.
- Tizimlarga ulanish (service JWT, connector'lar, real-time): 4–8-bosqichlar.
