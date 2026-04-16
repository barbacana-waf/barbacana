# Normal request to a regular path passes through.
GET {{host}}/api/config
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/api/config"
