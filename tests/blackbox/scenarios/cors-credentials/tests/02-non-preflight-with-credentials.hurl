# Non-preflight request with credentials gets origin reflected.
GET {{host}}/api
Origin: https://app.example.com
HTTP 200
[Asserts]
header "Access-Control-Allow-Origin" == "https://app.example.com"
header "Access-Control-Allow-Credentials" == "true"
