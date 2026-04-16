# Clean parameter value passes through without blocking.
GET {{host}}/proxy
[QueryStringParams]
url: products
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
