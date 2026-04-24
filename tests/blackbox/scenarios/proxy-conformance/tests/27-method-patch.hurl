# PATCH must arrive as PATCH.
PATCH {{host}}/conformance/resource/1
Content-Type: application/json
{"name":"patched"}

HTTP 200
[Asserts]
jsonpath "$._request.method" == "PATCH"
jsonpath "$._request.body" == "{\"name\":\"patched\"}"
