# X-Frame-Options absent when header-x-frame-options is disabled.
GET {{host}}/test
HTTP 200
[Asserts]
header "X-Frame-Options" not exists
header "Content-Security-Policy" exists
header "Permissions-Policy" exists
