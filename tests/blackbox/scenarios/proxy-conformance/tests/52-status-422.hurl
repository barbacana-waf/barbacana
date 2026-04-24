GET {{host}}/conformance/status/422

HTTP 422
[Asserts]
jsonpath "$.code" == 422
