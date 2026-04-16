# Request with unique query parameters passes through.
GET {{host}}/search
[QueryStringParams]
q: hello
page: 1
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/search"
