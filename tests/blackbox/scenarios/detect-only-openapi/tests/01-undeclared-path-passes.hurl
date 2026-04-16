# In detect-only mode, request to undeclared path passes through despite OpenAPI spec enforcing /users only.
GET {{host}}/admin/secret
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/admin/secret"
