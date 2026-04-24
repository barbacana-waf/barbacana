# Status 200 must pass through unchanged.
GET {{host}}/conformance/status/200

HTTP 200
[Asserts]
jsonpath "$.code" == 200
jsonpath "$._request.method" == "GET"
