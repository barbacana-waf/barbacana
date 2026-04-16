# Full path rewrite: any request path becomes /health at upstream.
GET {{host}}/anything/here
HTTP 200
[Asserts]
jsonpath "$.path" == "/health"
