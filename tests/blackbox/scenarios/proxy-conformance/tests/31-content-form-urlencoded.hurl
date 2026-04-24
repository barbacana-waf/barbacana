# application/x-www-form-urlencoded body must reach the upstream intact.
# [FormParams] makes hurl serialize fields as key=value pairs and set the
# Content-Type automatically.
POST {{host}}/conformance/content/form
[FormParams]
username: alice
role: admin

HTTP 200
[Asserts]
jsonpath "$._request.method" == "POST"
jsonpath "$._request.content_type" == "application/x-www-form-urlencoded"
jsonpath "$.fields.username" == "alice"
jsonpath "$.fields.role" == "admin"
