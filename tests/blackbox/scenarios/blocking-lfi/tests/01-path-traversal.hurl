# Local file inclusion via path traversal in query parameter.
GET {{host}}/page
[QueryStringParams]
file: ../../../../etc/passwd
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
