# Method override header is stripped before reaching the upstream.
GET {{host}}/test
X-HTTP-Method-Override: DELETE
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers.X-Http-Method-Override" not exists
