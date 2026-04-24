# Upstream uses Transfer-Encoding: chunked. Hurl handles the framing;
# we only verify the decoded body arrived intact and parses as JSON.
GET {{host}}/conformance/chunked

HTTP 200
[Asserts]
jsonpath "$.chunks" count == 3
jsonpath "$.chunks[0]" == "first"
jsonpath "$.chunks[2]" == "third"
