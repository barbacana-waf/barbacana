# /api/* clean GET — accept.content_types restricts bodies but the
# request has no body, so it passes.
GET {{host}}/api/users/42
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/users/42"
