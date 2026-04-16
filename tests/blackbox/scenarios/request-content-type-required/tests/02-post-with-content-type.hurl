# POST with Content-Type passes.
POST {{host}}/data
Content-Type: application/json
{"key": "value"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
