# Cross-origin POST: Origin not in CORS allow_origins, blocked with 403.
POST {{host}}/api/echo
Origin: http://evil.com
Content-Type: application/json
`{"ok":true}`
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
