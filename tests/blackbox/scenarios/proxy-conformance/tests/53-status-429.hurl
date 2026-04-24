# Status 429 must carry the Retry-After hint through.
GET {{host}}/conformance/status/429

HTTP 429
[Asserts]
header "Retry-After" exists
jsonpath "$.code" == 429
