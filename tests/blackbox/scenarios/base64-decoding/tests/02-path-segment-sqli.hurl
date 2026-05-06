# SQLi payload base64-encoded inside a path segment — the
# base64-decoding stage decodes the segment and CRS catches the SQLi.
GET {{host}}/JyBPUiAxPTEtLQ==/users
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
