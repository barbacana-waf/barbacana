# X-HTTP-Method-Override header reaches upstream when method-override is disabled.
GET {{host}}/test
X-HTTP-Method-Override: PUT
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers.X-Http-Method-Override" == "PUT"
