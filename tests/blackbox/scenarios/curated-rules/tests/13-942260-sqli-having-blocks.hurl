# CRS 942260 — auth bypass via HAVING clause.
GET {{host}}/block/?q=%27or%201%3D1%20having%201
HTTP 403
