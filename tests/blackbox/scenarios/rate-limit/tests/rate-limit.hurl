# First request — within rps budget, allowed.
GET {{host}}/api/hello
HTTP 200

# Second request — exactly at rps limit, allowed.
GET {{host}}/api/hello
HTTP 200

# Third request — exceeds rps, rejected with 429 and Retry-After.
GET {{host}}/api/hello
HTTP 429
[Asserts]
header "Retry-After" == "1"
header "Content-Type" contains "application/json"
jsonpath "$.error" == "blocked"
jsonpath "$.request_id" isString
jsonpath "$.request_id" != ""
