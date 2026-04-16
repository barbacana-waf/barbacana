# GET /users is declared in the OpenAPI spec and passes.
GET {{host}}/users
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/users"
