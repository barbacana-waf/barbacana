# Percent-encoded characters must decode correctly at the upstream.
GET {{host}}/conformance/query/echo?email=user%2Btag%40example.com&path=%2Fusr%2Flocal

HTTP 200
[Asserts]
jsonpath "$.params.email[0]" == "user+tag@example.com"
jsonpath "$.params.path[0]" == "/usr/local"
