# Status 400 error responses must pass through unmodified.
GET {{host}}/conformance/status/400

HTTP 400
[Asserts]
jsonpath "$.code" == 400
