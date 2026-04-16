# Disabling double-encoding does not affect null-byte-injection protection.
GET {{host}}/page%00evil
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
