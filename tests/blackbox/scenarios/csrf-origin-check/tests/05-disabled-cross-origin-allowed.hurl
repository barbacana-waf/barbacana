# Same payload as 02 but on a route with csrf-origin-check disabled —
# the request now reaches the upstream untouched.
POST {{host}}/disabled/echo
Origin: http://evil.com
Content-Type: application/json
`{"ok":true}`
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
