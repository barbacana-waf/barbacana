# Strict preset produces a more restrictive CSP than moderate.
GET {{host}}/test
HTTP 200
[Asserts]
header "Content-Security-Policy" contains "default-src 'none'"
header "X-Frame-Options" == "DENY"
header "Cross-Origin-Embedder-Policy" == "require-corp"
