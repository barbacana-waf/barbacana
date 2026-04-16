# POST /users with conformant body passes.
POST {{host}}/users
Content-Type: application/json
{"name": "alice"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/users"
