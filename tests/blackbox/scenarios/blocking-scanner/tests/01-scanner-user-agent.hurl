# Scanner user-agent triggers detection.
GET {{host}}/
User-Agent: sqlmap/1.0-dev
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
