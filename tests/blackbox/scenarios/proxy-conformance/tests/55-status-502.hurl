GET {{host}}/conformance/status/502

HTTP 502
[Asserts]
jsonpath "$.code" == 502
