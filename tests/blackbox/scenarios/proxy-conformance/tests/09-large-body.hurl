# ~900KB JSON response — a coarse check that Barbacana does not truncate
# long responses or buffer them in a way that corrupts the payload.
GET {{host}}/conformance/large-body

HTTP 200
[Asserts]
header "Content-Type" contains "application/json"
bytes count > 500000
jsonpath "$" count == 10000
jsonpath "$[0].id" == 0
jsonpath "$[9999].id" == 9999
