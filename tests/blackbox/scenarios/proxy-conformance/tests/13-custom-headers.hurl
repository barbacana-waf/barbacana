# Unusual but valid response headers must propagate to the client.
# X-Multi is intentionally emitted twice upstream; at least one value
# must survive the proxy (some proxies merge duplicates into a single
# comma-joined value — both are acceptable here).
GET {{host}}/conformance/custom-headers

HTTP 200
[Asserts]
header "X-Custom-One" == "value-one"
header "X-Custom-Two" == "value with spaces"
header "X-Multi" exists
