# Trailing slash must be preserved end-to-end.
GET {{host}}/conformance/path/trailing-slash/

HTTP 200
[Asserts]
jsonpath "$._request.path" endsWith "/"
