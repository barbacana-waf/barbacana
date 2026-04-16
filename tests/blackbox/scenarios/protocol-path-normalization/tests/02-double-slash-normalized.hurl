# Double slash in path is normalized before forwarding to upstream.
GET {{host}}//api//users
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/users"
