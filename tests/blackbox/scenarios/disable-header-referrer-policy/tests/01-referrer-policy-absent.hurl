# When header-referrer-policy is disabled, Referrer-Policy header is not injected.
GET {{host}}/test
HTTP 200
[Asserts]
header "Referrer-Policy" not exists
