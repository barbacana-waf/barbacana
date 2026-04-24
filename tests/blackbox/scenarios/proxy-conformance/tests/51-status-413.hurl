GET {{host}}/conformance/status/413

HTTP 413
[Asserts]
jsonpath "$.code" == 413
