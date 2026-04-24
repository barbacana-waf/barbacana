# PUT must arrive as PUT, not converted to POST.
PUT {{host}}/conformance/resource/1
Content-Type: application/json
{"name":"updated"}

HTTP 200
[Asserts]
jsonpath "$._request.method" == "PUT"
jsonpath "$._request.body" == "{\"name\":\"updated\"}"
jsonpath "$._request.content_type" == "application/json"
jsonpath "$.name" == "updated"
