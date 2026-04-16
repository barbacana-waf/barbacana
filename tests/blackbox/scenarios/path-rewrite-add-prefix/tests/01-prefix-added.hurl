# add_prefix: /backend prepends to the path before forwarding.
GET {{host}}/users
HTTP 200
[Asserts]
jsonpath "$.path" == "/backend/users"
