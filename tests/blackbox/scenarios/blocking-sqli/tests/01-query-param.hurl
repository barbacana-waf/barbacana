# Classic OR 1=1 authentication bypass in query parameter.
GET {{host}}/login
[QueryStringParams]
user: admin
pass: ' OR 1=1--
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
