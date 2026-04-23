# CRS 942340 — auth bypass via IN (SELECT ...).
GET {{host}}/block/?q=%27%20in%20%28select%201%29
HTTP 403
