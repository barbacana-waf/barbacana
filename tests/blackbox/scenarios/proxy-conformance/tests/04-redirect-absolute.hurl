# Upstream returns Location: http://localhost:19000/conformance/echo.
# Barbacana's current behaviour passes the upstream's absolute URL
# through unchanged. If a future change rewrites Location to the
# WAF-facing host, update this assertion.
GET {{host}}/conformance/redirect-absolute

HTTP 302
[Asserts]
header "Location" exists
header "Location" == "http://localhost:19000/conformance/echo"
