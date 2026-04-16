# Upstream sets X-Powered-By header; WAF strips it.
# The upstream echo confirms it was set (visible in body), but the
# response header is absent.
GET {{host}}/test
HTTP 200
[Asserts]
header "X-Powered-By" not exists
