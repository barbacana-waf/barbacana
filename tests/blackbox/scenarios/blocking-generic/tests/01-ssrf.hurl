# SSRF attempt via cloud metadata endpoint in query parameter.
GET {{host}}/proxy
[QueryStringParams]
url: http://169.254.169.254/latest/meta-data/
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
