# The actual cross-origin PATCH from the same SPA origin is forwarded to
# the upstream and the response carries the reflected Allow-Origin so the
# browser exposes it to JavaScript.
PATCH {{host}}/api/users/42
Origin: https://app.example.com
Authorization: Bearer test-token
Content-Type: application/json
X-Request-Id: req-123
{"name": "alice"}
HTTP 200
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Credentials" == "true"
jsonpath "$.method" == "PATCH"
jsonpath "$.path" == "/api/users/42"
