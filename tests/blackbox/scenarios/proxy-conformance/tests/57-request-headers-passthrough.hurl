# Arbitrary request headers must reach the upstream. /conformance/headers/echo
# lowercases keys in the JSON response.
GET {{host}}/conformance/headers/echo
X-Custom-App: my-service
X-Request-Id: req-abc-123
Accept-Language: en-US,es

HTTP 200
[Asserts]
jsonpath "$.x-custom-app" == "my-service"
jsonpath "$.x-request-id" == "req-abc-123"
jsonpath "$.accept-language" == "en-US,es"
