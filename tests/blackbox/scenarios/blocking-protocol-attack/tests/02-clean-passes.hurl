# Normal search query passes through.
GET {{host}}/search
[QueryStringParams]
q: hello world
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/search"
