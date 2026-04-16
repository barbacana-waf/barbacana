# Clean numeric parameter passes through without blocking.
GET {{host}}/page
[QueryStringParams]
id: 1
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
