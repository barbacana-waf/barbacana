# Valid integer path parameter passes through.
GET {{host}}/users/42
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/users/42"
