# GET on a resource must arrive as GET with the exact path.
GET {{host}}/conformance/resource/1

HTTP 200
[Asserts]
jsonpath "$._request.method" == "GET"
jsonpath "$._request.path" == "/conformance/resource/1"
jsonpath "$.id" == 1
jsonpath "$.name" == "example"
