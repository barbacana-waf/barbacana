# Same-origin POST: Origin matches CORS allow_origins, request passes.
# Body is single-line JSON to avoid tripping CRS 921150 (header
# injection via CRLF in body), which would mask the origin-check
# decision under test.
POST {{host}}/api/echo
Origin: http://localhost:18080
Content-Type: application/json
`{"ok":true}`
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
