# Null byte in URL path is rejected.
GET {{host}}/test%00malicious
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
