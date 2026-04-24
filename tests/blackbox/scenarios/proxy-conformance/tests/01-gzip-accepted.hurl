# Accept-Encoding: gzip → upstream compresses; Barbacana must pass the
# encoded body and Content-Encoding header through untouched. Hurl's
# `compressed` option sends Accept-Encoding and decompresses the reply
# transparently so jsonpath operates on the decoded body.
GET {{host}}/conformance/gzip
[Options]
compressed: true

HTTP 200
[Asserts]
header "Content-Encoding" == "gzip"
jsonpath "$.message" == "hello"
jsonpath "$.compressed" == true
