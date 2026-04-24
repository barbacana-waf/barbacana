# Relative Location from upstream must reach the client unchanged.
GET {{host}}/conformance/redirect-relative

HTTP 302
[Asserts]
header "Location" == "/conformance/echo"
