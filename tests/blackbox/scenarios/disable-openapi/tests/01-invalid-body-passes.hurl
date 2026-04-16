# Invalid body passes when openapi-body is disabled.
POST {{host}}/users
Content-Type: application/json
{"invalid": "missing required name field"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/users"
