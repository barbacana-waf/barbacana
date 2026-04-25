# The custom CSP fully replaces the default `default-src 'self'; ...`
# value, so a browser will permit inline <script> blocks on this route.
# Other security headers from the moderate preset stay intact.
GET {{host}}/index.html
HTTP 200
[Asserts]
header "Content-Security-Policy" == "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
header "X-Frame-Options" == "DENY"
header "X-Content-Type-Options" == "nosniff"
