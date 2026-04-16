# When header-cache-control is disabled, Cache-Control header is not injected.
GET {{host}}/test
HTTP 200
[Asserts]
header "Cache-Control" not exists
