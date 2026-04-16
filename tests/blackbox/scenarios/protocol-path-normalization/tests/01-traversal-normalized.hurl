# Path with traversal sequence is normalized before forwarding to upstream.
# The WAF resolves /api/../users to /users — it does not block, it normalizes.
GET {{host}}/api/../users
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/users"
