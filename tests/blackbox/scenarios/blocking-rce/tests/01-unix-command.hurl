# Unix command injection via query parameter.
GET {{host}}/search
[QueryStringParams]
q: ;cat /etc/passwd
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
