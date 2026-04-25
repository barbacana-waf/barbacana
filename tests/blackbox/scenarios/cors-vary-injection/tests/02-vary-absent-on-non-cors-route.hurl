# Non-CORS route: cors-vary-injection must not run, so the response
# carries no CORS-related Vary value (and typically no Vary at all).
GET {{host}}/no-cors/echo
HTTP 200
[Asserts]
header "Vary" not contains "Origin"
