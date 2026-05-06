# Route disable beats global enable on equal specificity. The
# method-override-param leaf is OFF for this route despite the global
# enable, so the strip protection does NOT run and X-HTTP-Method-
# Override survives to upstream. The crs.go restricted-headers shim
# also takes effect (because the leaf is in the resolved disable map),
# so curated rule 920450 does not fire on the override headers either.
GET {{host}}/test
X-HTTP-Method-Override: PUT
HTTP 200
[Asserts]
jsonpath "$.method" == "GET"
jsonpath "$.headers['X-Http-Method-Override']" == "PUT"
