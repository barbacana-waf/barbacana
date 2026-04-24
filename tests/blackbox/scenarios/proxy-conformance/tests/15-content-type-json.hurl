GET {{host}}/conformance/content-types/json

HTTP 200
[Asserts]
header "Content-Type" startsWith "application/json"
jsonpath "$.type" == "json"
