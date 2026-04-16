# api-only preset: X-Content-Type-Options present, HSTS present, no X-Frame-Options.
GET {{host}}/test
HTTP 200
[Asserts]
header "X-Content-Type-Options" == "nosniff"
header "Strict-Transport-Security" exists
header "Cache-Control" exists
