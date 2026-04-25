# Preflight for a PATCH carrying Authorization + X-Request-Id is answered
# by Barbacana with the configured allow lists, credentials, and max-age.
OPTIONS {{host}}/api/users/42
Origin: https://app.example.com
Access-Control-Request-Method: PATCH
Access-Control-Request-Headers: Authorization, Content-Type, X-Request-Id
HTTP 204
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Origin" != "*"
header "Access-Control-Allow-Credentials" == "true"
header "Access-Control-Allow-Methods" contains "PATCH"
header "Access-Control-Allow-Methods" contains "DELETE"
header "Access-Control-Allow-Headers" contains "Authorization"
header "Access-Control-Allow-Headers" contains "X-Request-Id"
header "Access-Control-Max-Age" == "3600"
header "Vary" contains "Origin"
