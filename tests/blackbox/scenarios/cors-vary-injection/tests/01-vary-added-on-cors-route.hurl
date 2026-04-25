# CORS-protected route: Vary must include Origin so a CDN does not
# serve a response cached for one Origin to a request from another.
GET {{host}}/cors/echo
HTTP 200
[Asserts]
header "Vary" contains "Origin"
header "Vary" contains "Access-Control-Request-Method"
header "Vary" contains "Access-Control-Request-Headers"
