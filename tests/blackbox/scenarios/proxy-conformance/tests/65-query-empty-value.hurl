# An empty-valued query parameter must reach the upstream as present-but-empty.
GET {{host}}/conformance/query/echo?flag=&name=test

HTTP 200
[Asserts]
jsonpath "$.params.flag[0]" == ""
jsonpath "$.params.name[0]" == "test"
