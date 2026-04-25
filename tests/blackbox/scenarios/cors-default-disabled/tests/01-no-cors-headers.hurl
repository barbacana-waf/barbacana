# Cross-origin GET from a browser-like client returns the upstream payload
# but no Access-Control-Allow-* headers, so the browser would block it.
GET {{host}}/api/data
Origin: https://app.example.com
HTTP 200
[Asserts]
header "Access-Control-Allow-Origin" not exists
header "Access-Control-Allow-Credentials" not exists
header "Access-Control-Allow-Methods" not exists
header "Access-Control-Allow-Headers" not exists
