# Normal request without RFI payload passes through.
GET {{host}}/page
[QueryStringParams]
id: 42
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/page"
