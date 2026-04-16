# In detect-only mode, LFI payload passes through to upstream.
GET {{host}}/page
[QueryStringParams]
file: ../../../../etc/passwd
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/page"
