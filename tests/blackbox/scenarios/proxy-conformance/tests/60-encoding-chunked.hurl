# Chunked transfer encoding must reach the client intact (hurl decodes it
# transparently; the assertion is that the full JSON reassembles).
GET {{host}}/conformance/encoding/chunked

HTTP 200
[Asserts]
jsonpath "$.encoding" == "chunked"
jsonpath "$._request.method" == "GET"
