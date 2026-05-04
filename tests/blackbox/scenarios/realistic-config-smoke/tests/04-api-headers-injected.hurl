# /api/* — CSP is set (opted in globally), the always-on baseline
# (HSTS, nosniff, referrer policy) is intact.
GET {{host}}/api/health
HTTP 200
[Asserts]
header "Content-Security-Policy" exists
header "Strict-Transport-Security" exists
header "X-Content-Type-Options" == "nosniff"
header "Referrer-Policy" exists
header "Cross-Origin-Opener-Policy" exists
header "Permissions-Policy" exists
