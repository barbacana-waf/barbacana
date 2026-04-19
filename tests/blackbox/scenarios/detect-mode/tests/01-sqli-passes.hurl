# In detect-only mode, SQLi payload passes through to upstream.
GET {{host}}/login
[QueryStringParams]
user: admin
pass: ' OR 1=1--
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/login"
