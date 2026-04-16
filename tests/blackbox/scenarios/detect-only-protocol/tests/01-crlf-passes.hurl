# In detect-only mode, CRLF injection payload passes through to upstream.
GET {{host}}/test%0d%0aInjected-Header:%20value
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
