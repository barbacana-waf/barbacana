# POST body must arrive byte-identical to what the client sent.
POST {{host}}/conformance/echo/body
Content-Type: application/json
{"key":"value","number":42}

HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
header "X-Request-Echo" exists
jsonpath "$.key" == "value"
jsonpath "$.number" == 42
