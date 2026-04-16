# Entire sql-injection category is disabled; boolean SQLi passes.
GET {{host}}/login
[QueryStringParams]
user: admin
pass: ' OR 1=1--
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/login"
