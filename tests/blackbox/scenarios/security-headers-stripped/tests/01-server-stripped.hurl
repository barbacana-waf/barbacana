# Upstream sets Server header; WAF strips it.
GET {{host}}/test
HTTP 200
[Asserts]
header "Server" not exists
