# Serverga o'rnatish (Debian 12)

Bu hujjat Admin BFF'ni Debian 12 (bookworm) serveriga birinchi marta
o'rnatish tartibi. Keyingi yangilashlar uchun `deploy/deploy.sh` ishlatiladi
(oxirgi bo'lim).

Server boshqa tizim (proktoring) bilan umumiy. Shuning uchun:

- **Boshqa tizimning servislariga tegilmaydi.** Serverdagi `redis-server.service`,
  PostgreSQL 15 klasteri va mavjud Nginx saytlari o'zgartirilmaydi va qayta
  ishga tushirilmaydi. BFF o'z Redis instansini va o'z PostgreSQL 17 klasterini
  ishlatadi.
- **Faqat aniq servislar boshqariladi.** `systemctl restart nginx`,
  `systemctl restart postgresql` va `systemctl restart redis-server` buyruqlari
  ishlatilmaydi. Nginx faqat `nginx -t`dan keyin `reload` qilinadi, PostgreSQL'da
  faqat `postgresql@17-main` boshqariladi.
- **Og'ir ishlar imtihon smenasidan tashqarida qilinadi.** Bu Python'ni yig'ish
  (1-qadam) va PGDG paketlarini o'rnatish (5-qadam).
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

Serverda tekshirib oling:

```bash
grep -n "include" /etc/nginx/nginx.conf          # sites-enabled/* ulanganmi
grep -rn "listen" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/
ss -ltnp | grep -E ':(5433|8081)\b'             # bo'sh bo'lishi kerak
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

## 5. PostgreSQL 17 (BFF'ning o'z klasteri)

Debian 12'dagi PostgreSQL 15 klasteri (port 5432) proktoringniki. BFF uchun
PGDG repo'sidan PostgreSQL 17 o'rnatiladi, u alohida klaster bo'lib 5433-portda
ishlaydi. Lokal testlar ham PostgreSQL 17'da o'tadi.

PGDG repo'si `postgresql-15` paketining yangiroq build'ini ham taklif qiladi.
Uni olsangiz, `apt upgrade` paytida proktoringning PostgreSQL'i qayta ishga
tushadi. Shuning uchun quyidagi pin fayli PGDG'dan faqat PostgreSQL 17'ga
kerakli paketlarni oladi.

```bash
install -d /usr/share/postgresql-common/pgdg
curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list

cat > /etc/apt/preferences.d/pgdg.pref <<'EOF'
# PGDG'dan faqat PostgreSQL 17 va uning bog'liqliklari olinadi.
# Proktoringning postgresql-15 paketi Debian'ning o'zidan yangilanadi.
Package: *
Pin: release o=apt.postgresql.org
Pin-Priority: 100

Package: postgresql-17 postgresql-client-17 postgresql-common postgresql-client-common libpq5 libpq-dev pgdg-keyring
Pin: release o=apt.postgresql.org
Pin-Priority: 500
EOF

apt update
apt-cache policy postgresql-15 postgresql-17
```

`apt-cache policy` natijasida ikkita narsa bo'lishi kerak:

- `postgresql-15` uchun `Candidate` Debian'niki, ya'ni `+deb12u` bilan tugaydi;
- `postgresql-17` uchun `Candidate` `apt.postgresql.org`dan.

Shunday bo'lmasa, keyingi qadamga o'tilmaydi.

```bash
apt install -y postgresql-17
pg_lsclusters                # 17 main 5433 online (15 main 5432 o'zgarmagan)

# Faqat unix socket, TCP yopiq.
pg_conftool 17 main set listen_addresses ''
systemctl restart postgresql@17-main
```

Port 5433 bo'lmasa, `admin-bff.env`dagi `DB_PORT` `pg_lsclusters`dagi port
bilan bir xil qilinadi.

Rollar va baza. Ikki rol kerak (README, "PostgreSQL rollari"). Parollar
fayllardan olinadi, buyruq qatorida ko'rinmaydi:

```bash
C=/etc/admin-bff/credentials
{
  printf "CREATE ROLE admin_bff_owner LOGIN PASSWORD '%s';\n" "$(cat $C/db_owner_password)"
  printf "CREATE ROLE admin_bff LOGIN PASSWORD '%s';\n" "$(cat $C/db_password)"
  echo "CREATE DATABASE admin_bff OWNER admin_bff_owner;"
  echo "REVOKE CONNECT, TEMPORARY ON DATABASE admin_bff FROM PUBLIC;"
  echo "GRANT CONNECT ON DATABASE admin_bff TO admin_bff_owner, admin_bff;"
} | runuser -u postgres -- psql -p 5433 -v ON_ERROR_STOP=1
```

`pg_hba.conf`da BFF qatori birinchi `local` qatoridan oldin turishi kerak.
Debian'ning `local all all peer` qatori OS user nomini talab qiladi, u esa
BFF'ga mos kelmaydi:

```bash
sed -i '0,/^local/s//local   admin_bff   admin_bff_owner,admin_bff   scram-sha-256\nlocal/' \
  /etc/postgresql/17/main/pg_hba.conf
grep -n '^local' /etc/postgresql/17/main/pg_hba.conf   # admin_bff qatori birinchi
systemctl reload postgresql@17-main
```

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
- `DB_PORT`: `pg_lsclusters`dagi 17-klaster porti;
- `REDIS_URL`: `unix:///run/admin-bff-redis/redis.sock?db=0`.

## 8. Migratsiyalar va servis

```bash
cd /srv/admin-bff
( set -a; . /etc/admin-bff/admin-bff.env; set +a
  APP_ENV=production CREDENTIALS_DIRECTORY=/etc/admin-bff/credentials \
  .venv/bin/alembic upgrade head )

cp /srv/admin-bff/deploy/admin-bff.service /etc/systemd/system/
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
- Redis paroli `credentials/redis_password` bilan bir xil emas.

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
tushmaydi. Unda `alembic downgrade`dan oldin bazaning nusxasi olinadi
(`runuser -u postgres -- pg_dump -p 5433 -Fc admin_bff > /root/admin_bff.dump`).

## Hozircha yo'q

- OneID: o'chiq, client yozilmagan (6-bo'lim).
- DB backup va audit retention: egasining qarori bilan qilinmaydi.
- Tizimlarga ulanish (service JWT, connector'lar, real-time): 4–8-bosqichlar.
