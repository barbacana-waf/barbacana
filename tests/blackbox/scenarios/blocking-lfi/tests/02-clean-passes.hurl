# Clean file parameter passes through without blocking.
GET {{host}}/page
[QueryStringParams]
file: report.pdf
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
