# Request body and Content-Type must survive an unmodified round-trip
# through Barbacana. The upstream echoes the body back as-is.
POST {{host}}/conformance/post-echo
Content-Type: application/json
{"test":"value","number":42}

HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
jsonpath "$.test" == "value"
jsonpath "$.number" == 42
