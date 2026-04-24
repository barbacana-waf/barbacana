# Query string must arrive intact at the upstream.
GET {{host}}/conformance/echo?foo=bar&baz=123

HTTP 200
[Asserts]
jsonpath "$.query.foo[0]" == "bar"
jsonpath "$.query.baz[0]" == "123"
