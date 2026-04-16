# strip_prefix: /api/v1 removes the prefix before forwarding to upstream.
GET {{host}}/api/v1/users
HTTP 200
[Asserts]
jsonpath "$.path" == "/users"
