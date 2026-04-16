# Normal request without double-encoding passes through.
GET {{host}}/page?q=hello
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/page"
