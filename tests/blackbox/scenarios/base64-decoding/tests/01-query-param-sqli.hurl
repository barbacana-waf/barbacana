# SQLi payload base64-encoded inside a query parameter — the
# base64-decoding stage decodes it and CRS catches the SQLi.
GET {{host}}/login?q=JyBPUiAxPTEtLQ==
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
