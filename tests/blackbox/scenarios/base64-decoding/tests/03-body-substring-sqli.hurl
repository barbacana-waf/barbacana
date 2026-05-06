# JSON body with an embedded base64-encoded SQLi blob — the body
# scanner finds the run, decodes it, and CRS catches the SQLi.
POST {{host}}/api/payload
Content-Type: application/json
{"payload":"JyBPUiAxPTEtLQ=="}
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
