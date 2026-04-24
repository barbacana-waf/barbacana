# No Accept-Encoding: upstream returns uncompressed JSON. Barbacana must
# not inject Accept-Encoding upstream nor transform the body.
GET {{host}}/conformance/gzip

HTTP 200
[Asserts]
header "Content-Encoding" not exists
jsonpath "$.message" == "hello"
jsonpath "$.compressed" == false
