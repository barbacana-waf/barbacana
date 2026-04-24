# Percent-encoded space in the path: we intentionally assert on "space"
# (substring) so the test records what arrives at the upstream — decoded
# ("with space") or still-encoded ("with%20space"). Either form is a
# valid transparent passthrough.
GET {{host}}/conformance/path/with%20space

HTTP 200
[Asserts]
jsonpath "$._request.path" contains "space"
jsonpath "$._request.path" startsWith "/conformance/path/with"
