# Normal header count and size passes.
GET {{host}}/test
X-Foo: bar
X-Baz: qux
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
