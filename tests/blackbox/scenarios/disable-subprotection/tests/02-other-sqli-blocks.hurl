# Other protections still active; CRLF injection is still blocked.
GET {{host}}/test%0d%0aInjected:%20value
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
