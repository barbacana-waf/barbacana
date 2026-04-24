# Identity encoding: explicit Content-Length, no Transfer-Encoding.
GET {{host}}/conformance/encoding/identity

HTTP 200
[Asserts]
header "Content-Length" exists
jsonpath "$.encoding" == "identity"
