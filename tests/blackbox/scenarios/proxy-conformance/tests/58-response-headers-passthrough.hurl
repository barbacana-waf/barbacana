# Response headers from the upstream must reach the client unchanged.
GET {{host}}/conformance/headers/response

HTTP 200
[Asserts]
header "Content-Language" == "en-US"
header "X-Request-Id" == "req-12345"
header "X-Correlation-Id" == "corr-67890"
header "Link" exists
header "Retry-After" == "30"
