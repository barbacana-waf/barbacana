# Repeated query parameter keys must reach the upstream as an ordered list.
GET {{host}}/conformance/query/echo?tag=a&tag=b&tag=c

HTTP 200
[Asserts]
jsonpath "$.params.tag" count == 3
jsonpath "$.params.tag[0]" == "a"
jsonpath "$.params.tag[1]" == "b"
jsonpath "$.params.tag[2]" == "c"
