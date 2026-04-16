# Clean GET request reaches the upstream and returns 200.
GET {{host}}/hello
HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.method" == "GET"
jsonpath "$.path" == "/hello"
