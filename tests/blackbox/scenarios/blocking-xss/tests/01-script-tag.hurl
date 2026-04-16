# XSS via script tag in query parameter.
GET {{host}}/search
[QueryStringParams]
q: <script>alert('xss')</script>
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
