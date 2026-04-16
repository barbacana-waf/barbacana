# POST with correct JSON content-type passes.
POST {{host}}/items
Content-Type: application/json
{"name": "test"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
