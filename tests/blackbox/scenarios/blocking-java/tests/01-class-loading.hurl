# Java injection via Runtime class loading in query parameter.
GET {{host}}/api
[QueryStringParams]
class: java.lang.Runtime.getRuntime().exec('id')
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
