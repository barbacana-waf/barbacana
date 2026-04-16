# XSS is still active even though sql-injection is disabled.
GET {{host}}/search
[QueryStringParams]
q: <script>alert(1)</script>
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
