# The custom-headers endpoint also emits Server and X-Powered-By so
# Barbacana's default strip list can be verified end-to-end.
GET {{host}}/conformance/custom-headers

HTTP 200
[Asserts]
header "Server" not exists
header "X-Powered-By" not exists
