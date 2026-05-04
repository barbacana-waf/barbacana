# /public/* — CORS configured for app.example.com. A preflight from
# that origin succeeds with the configured allow-list echoed back.
OPTIONS {{host}}/public/data.json
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type
HTTP 204
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Methods" contains "POST"
