# Entire sql-injection category is disabled; UNION SELECT passes.
GET {{host}}/search
[QueryStringParams]
q: 1 UNION SELECT username,password FROM users--
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/search"
