# Clean search query passes through without blocking.
GET {{host}}/search
[QueryStringParams]
q: hello world
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
