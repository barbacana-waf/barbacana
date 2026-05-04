# Upstream's Server / X-Powered-By headers are stripped by the
# default-on response-headers-remove-* leaves regardless of route.
GET {{host}}/api/health
HTTP 200
[Asserts]
header "Server" not exists
header "X-Powered-By" not exists
