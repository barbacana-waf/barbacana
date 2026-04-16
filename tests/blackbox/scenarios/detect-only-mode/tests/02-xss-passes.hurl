# In detect-only mode, XSS payload passes through to upstream.
GET {{host}}/search
[QueryStringParams]
q: <script>alert(1)</script>
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/search"
