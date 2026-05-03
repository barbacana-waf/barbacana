# http-compliance-restricted-headers lives in the http-compliance-headers
# bucket — a sibling of character-encoding. It is NOT covered by the
# enable directive, so the L1 disable wins for it: the X-HTTP-Method-
# Override header reaches upstream unblocked.
GET {{host}}/test
X-HTTP-Method-Override: PUT
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers.X-Http-Method-Override" == "PUT"
