# XSS via event handler attribute in query parameter.
GET {{host}}/search
[QueryStringParams]
q: <img src=x onerror=alert(1)>
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
