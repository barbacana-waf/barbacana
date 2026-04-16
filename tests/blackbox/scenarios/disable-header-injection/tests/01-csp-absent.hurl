# Content-Security-Policy is absent when header-csp is disabled.
GET {{host}}/test
HTTP 200
[Asserts]
header "Content-Security-Policy" not exists
header "X-Frame-Options" == "DENY"
header "X-Content-Type-Options" == "nosniff"
