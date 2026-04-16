# Request from unlisted origin does not receive CORS headers.
GET {{host}}/api/data
Origin: https://evil.example.com
HTTP 200
[Asserts]
header "Access-Control-Allow-Origin" not exists
