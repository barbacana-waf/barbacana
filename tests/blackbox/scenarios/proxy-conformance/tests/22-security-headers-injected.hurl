# Default security headers must be injected AND upstream headers must
# survive — both coexist without conflict.
GET {{host}}/conformance/custom-headers

HTTP 200
[Asserts]
header "X-Content-Type-Options" == "nosniff"
header "X-Frame-Options" == "DENY"
header "Strict-Transport-Security" exists
header "Content-Security-Policy" exists
header "Referrer-Policy" exists
header "X-Custom-One" == "value-one"
header "X-Custom-Two" == "value with spaces"
