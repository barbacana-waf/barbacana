# CRS 932300 — SMTP RCPT TO injection via literal \r\n (decoded by t:escapeSeqDecode).
GET {{host}}/block/?to=%5Cr%5CnRCPT%20TO%3A%3Ca%40b.c%3E
HTTP 403
