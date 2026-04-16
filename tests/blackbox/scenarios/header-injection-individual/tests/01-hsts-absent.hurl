# HSTS header is absent when header-hsts is disabled.
GET {{host}}/test
HTTP 200
[Asserts]
header "Strict-Transport-Security" not exists
header "X-Content-Type-Options" == "nosniff"
header "Referrer-Policy" exists
header "Cross-Origin-Opener-Policy" exists
