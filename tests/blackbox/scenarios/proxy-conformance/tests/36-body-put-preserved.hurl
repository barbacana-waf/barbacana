# PUT body must arrive byte-identical.
PUT {{host}}/conformance/echo/body
Content-Type: application/json
{"key":"updated"}

HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
header "X-Request-Echo" exists
jsonpath "$.key" == "updated"
