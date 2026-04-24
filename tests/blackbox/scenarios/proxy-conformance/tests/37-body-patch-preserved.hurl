# PATCH body must arrive byte-identical.
PATCH {{host}}/conformance/echo/body
Content-Type: application/json
{"partial":true}

HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
header "X-Request-Echo" exists
jsonpath "$.partial" == true
