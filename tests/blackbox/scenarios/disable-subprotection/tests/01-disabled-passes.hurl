# null-byte-injection is disabled; null byte in URL passes through.
GET {{host}}/test%00value
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
