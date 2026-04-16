# CRLF injection in URL path is rejected.
GET {{host}}/test%0d%0aInjected-Header:%20value
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
