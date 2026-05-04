# /api/* — classic SQLi in query parameter blocks at the default-on
# sql-injection-* family.
GET {{host}}/api/search
[QueryStringParams]
q: ' UNION SELECT username, password FROM users--
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
