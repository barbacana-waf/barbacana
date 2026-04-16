# Shell expression injection via query parameter.
GET {{host}}/search
[QueryStringParams]
q: $(whoami)
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
