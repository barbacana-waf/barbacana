# Same payload bytes that pass as a multipart file part MUST block when
# placed in a query parameter — proves the rule is on and effective,
# the file-part bypass in test 01 is a property of multipart parsing
# (file bodies are not ARGS), not a rule weakness.
GET {{host}}/?code=alert.call(null,%201)
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
