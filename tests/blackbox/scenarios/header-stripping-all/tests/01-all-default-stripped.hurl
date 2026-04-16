# All upstream info-leak headers are stripped by default.
GET {{host}}/test
HTTP 200
[Asserts]
header "Server" not exists
header "X-Powered-By" not exists
