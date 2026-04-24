GET {{host}}/conformance/status/500

HTTP 500
[Asserts]
jsonpath "$.code" == 500
