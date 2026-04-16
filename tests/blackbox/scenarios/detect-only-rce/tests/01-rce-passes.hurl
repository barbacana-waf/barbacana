# In detect-only mode, RCE payload passes through to upstream.
GET {{host}}/cmd
[QueryStringParams]
exec: ;cat /etc/passwd
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/cmd"
