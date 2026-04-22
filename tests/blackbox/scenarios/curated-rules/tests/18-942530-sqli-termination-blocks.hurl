# CRS 942530 — SQLi query termination: quote followed by semicolon.
GET {{host}}/block/?q=%27%3B
HTTP 403
