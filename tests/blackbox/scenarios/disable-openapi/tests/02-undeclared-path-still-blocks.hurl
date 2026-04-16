# Undeclared path still blocks (only openapi-body disabled).
GET {{host}}/unknown
HTTP 404
[Asserts]
jsonpath "$.error" exists
