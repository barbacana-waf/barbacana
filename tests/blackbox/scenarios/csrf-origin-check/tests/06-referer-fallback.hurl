# Origin missing but Referer matches: the check extracts the origin
# (scheme+host+port) from the Referer URL and accepts it.
POST {{host}}/api/echo
Referer: http://localhost:18080/some/page
Content-Type: application/json
`{"ok":true}`
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
