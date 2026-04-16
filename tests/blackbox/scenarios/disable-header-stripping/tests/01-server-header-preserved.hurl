# Server header is preserved when strip-server is disabled.
GET {{host}}/test
HTTP 200
[Asserts]
header "Server" exists
header "X-Powered-By" not exists
