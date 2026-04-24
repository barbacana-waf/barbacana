# Status 503 must carry the Retry-After hint through.
GET {{host}}/conformance/status/503

HTTP 503
[Asserts]
header "Retry-After" exists
jsonpath "$.code" == 503
