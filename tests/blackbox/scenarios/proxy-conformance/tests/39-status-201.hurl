# Status 201 with Location header must pass through.
GET {{host}}/conformance/status/201

HTTP 201
[Asserts]
header "Location" exists
jsonpath "$.code" == 201
