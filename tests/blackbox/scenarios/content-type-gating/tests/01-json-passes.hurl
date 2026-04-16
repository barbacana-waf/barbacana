# POST with application/json is accepted.
POST {{host}}/api/data
Content-Type: application/json
{"key": "value"}
HTTP 200
[Asserts]
jsonpath "$.method" == "POST"
jsonpath "$.path" == "/api/data"
