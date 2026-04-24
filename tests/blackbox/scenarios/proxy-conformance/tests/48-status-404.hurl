# Status 404 must pass through.
GET {{host}}/conformance/status/404

HTTP 404
[Asserts]
jsonpath "$.code" == 404
