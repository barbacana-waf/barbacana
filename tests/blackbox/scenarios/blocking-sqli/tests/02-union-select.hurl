# UNION SELECT injection in query parameter.
GET {{host}}/search
[QueryStringParams]
q: 1 UNION SELECT username,password FROM users--
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
