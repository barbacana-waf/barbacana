# When header-permissions-policy is disabled, Permissions-Policy header is not injected.
GET {{host}}/test
HTTP 200
[Asserts]
header "Permissions-Policy" not exists
