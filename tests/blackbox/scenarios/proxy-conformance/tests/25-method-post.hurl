# POST must arrive as POST with Content-Type and body preserved verbatim.
POST {{host}}/conformance/resource
Content-Type: application/json
{"name":"test"}

HTTP 201
[Asserts]
header "Location" exists
jsonpath "$._request.method" == "POST"
jsonpath "$._request.body" == "{\"name\":\"test\"}"
jsonpath "$._request.content_type" == "application/json"
jsonpath "$.id" == 1
jsonpath "$.name" == "test"
