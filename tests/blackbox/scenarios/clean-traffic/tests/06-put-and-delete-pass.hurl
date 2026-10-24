PUT {{host}}/items/7
Content-Type: application/json
{"name": "widget", "price": 9.5}
HTTP 200
[Asserts]
jsonpath "$.method" == "PUT"

DELETE {{host}}/items/7
HTTP 200
[Asserts]
jsonpath "$.method" == "DELETE"
