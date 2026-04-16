# Remote file inclusion via IP-based URL in query parameter.
# Combines rfi-ip-parameter (IP in URL) and rfi-trailing-question (trailing ?) — both CRS 931xxx.
GET {{host}}/page
[QueryStringParams]
file: http://127.0.0.1/shell.php?
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
