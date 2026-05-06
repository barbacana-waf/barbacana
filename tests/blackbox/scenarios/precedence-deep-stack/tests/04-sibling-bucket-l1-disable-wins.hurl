# http-compliance-restricted-headers lives in the http-compliance-headers
# bucket — a sibling of the enabled character-encoding bucket. No
# directive at L2 or leaf level covers it, so the global L1 disable
# (spec 0) is the only covering directive and wins by default. The
# X-HTTP-Method-Override header reaches upstream unblocked.
GET {{host}}/test
X-HTTP-Method-Override: PUT
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers['X-Http-Method-Override']" == "PUT"
