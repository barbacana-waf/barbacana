# Disabling the new response-phase categories must not weaken request-phase
# protections. An SQL injection attack in a query parameter still blocks.
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
