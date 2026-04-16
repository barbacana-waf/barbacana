# Null byte injection still blocks (only method-override disabled).
GET {{host}}/test%00
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
