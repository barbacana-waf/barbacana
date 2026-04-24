GET {{host}}/conformance/status/409

HTTP 409
[Asserts]
jsonpath "$.code" == 409
