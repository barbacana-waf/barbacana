# Preflight with credentials reflects specific origin, not wildcard.
OPTIONS {{host}}/api
Origin: https://app.example.com
Access-Control-Request-Method: POST
HTTP 204
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Credentials" == "true"
header "Access-Control-Allow-Origin" != "*"
header "Vary" contains "Origin"
