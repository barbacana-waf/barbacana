# Session fixation via Set-Cookie meta tag injection in query parameter.
GET {{host}}/page
[QueryStringParams]
session: <meta http-equiv=Set-Cookie content="sessionid=abc">
HTTP 403
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
