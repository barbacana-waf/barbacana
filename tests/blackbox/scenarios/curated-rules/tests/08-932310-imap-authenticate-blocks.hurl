# CRS 932310 — IMAP AUTHENTICATE after CRLF (trailing CRLF required by regex).
GET {{host}}/block/?c=%5Cr%5CntagX%20AUTHENTICATE%20plain%5Cr%5Cn
HTTP 403
