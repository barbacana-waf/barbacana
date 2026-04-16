# Preflight from allowed origin returns 204 with CORS headers.
OPTIONS {{host}}/api/data
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization, Content-Type
HTTP 204
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Methods" contains "POST"
header "Access-Control-Allow-Headers" contains "Authorization"
header "Access-Control-Max-Age" == "600"
