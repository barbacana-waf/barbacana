# Normal GET request passes through with multipart-attack protection enabled.
GET {{host}}/upload
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/upload"
