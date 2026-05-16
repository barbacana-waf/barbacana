# In detect-only mode, requests that exceed the rps budget pass through to upstream.
# All three requests return 200 — the third would be 429 in blocking mode.

# First request — within rps budget.
GET {{host}}/api/hello
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/hello"

# Second request — exactly at rps limit.
GET {{host}}/api/hello
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/hello"

# Third request — would be rejected (429) in blocking mode; passes in detect-only.
GET {{host}}/api/hello
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/hello"
