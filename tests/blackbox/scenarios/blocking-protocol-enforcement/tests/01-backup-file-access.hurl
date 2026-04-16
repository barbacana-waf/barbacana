# Attempt to access a backup file (.bak) is blocked by CRS 920xxx.
GET {{host}}/config.bak
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
