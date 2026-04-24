# Simple key=value query parameters arrive intact.
GET {{host}}/conformance/query/echo?name=alice&age=30

HTTP 200
[Asserts]
jsonpath "$._request.query" contains "name=alice"
jsonpath "$._request.query" contains "age=30"
jsonpath "$.params.name[0]" == "alice"
jsonpath "$.params.age[0]" == "30"
