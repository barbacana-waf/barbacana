# CRS 942180 — basic SQL auth bypass (quote + boolean + comparator).
GET {{host}}/block/?q=%27%20or%201%3D1
HTTP 403
