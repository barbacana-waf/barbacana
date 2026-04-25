# Same route shape as /cors/* but with cors-vary-injection disabled —
# Barbacana must not append the CORS-related Vary values.
GET {{host}}/disabled/echo
HTTP 200
[Asserts]
header "Vary" not contains "Access-Control-Request-Method"
header "Vary" not contains "Access-Control-Request-Headers"
