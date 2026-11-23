"""`/api/v1` routerlari: barcha HTTP endpoint'lar shu yerda.

* `auth`: kirish, sessiyalar, parol, OneID (6-bo'lim);
* `me`: joriy admin;
* `admin`: adminlar, rollar, permission'lar (7-bo'lim);
* `audit`: audit log va eksport (9-bo'lim).

Mantiq router'larda emas, modullarning servislarida (`app/auth`, `app/rbac`,
`app/audit`). Keyingi bosqichlarda meta, dashboard, systems, clients, events
va jobs qo'shiladi.
"""
